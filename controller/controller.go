package controller

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"jwt-todo/auth"
	"jwt-todo/message"
	"jwt-todo/models"
	"net/http"
	"os"
	"strconv"

	"github.com/dgrijalva/jwt-go"
)

var user = models.User{
	ID:       1,
	UserName: "username",
	Password: "password",
	Phone:    "5558665422256", //this is a random number
}

func Login(rw http.ResponseWriter, r *http.Request) {

	u := models.User{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	json.Unmarshal(body, &u)

	rw.Header().Set("content-type", "application/json")

	//Compare the user from the request, with the one we defined:
	if user.UserName != u.UserName || user.Password != u.Password {
		rw.WriteHeader(http.StatusUnauthorized)
		fmt.Println("Please provide valid login details")
		return
	}
	ts, err := auth.CreateToken(user.ID)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		rw.WriteHeader(http.StatusUnprocessableEntity)
		rw.Write([]byte(err.Error()))
		return
	}
	saveErr := auth.CreateAuth(user.ID, ts)
	if saveErr != nil {
		fmt.Printf("err: %v\n", err)
		rw.WriteHeader(http.StatusUnprocessableEntity)
		rw.Write([]byte(saveErr.Error()))
		return
	}
	tokens := map[string]string{
		"access_token":  ts.AccessToken,
		"refresh_token": ts.RefreshToken,
	}

	response, _ := json.Marshal(tokens)
	rw.Header().Set("content-type", "application/json")
	rw.WriteHeader(http.StatusOK)
	rw.Write(response)
	// We have both the access_token and the refresh_token, and also have token metadata persisted in redis.
}

func CreateTodo(rw http.ResponseWriter, r *http.Request) {
	td := models.Todo{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Printf("err: %v\n", err)
		return
	}
	json.Unmarshal(body, &td)
	rw.Header().Set("content-type", "application/json")

	tokenAuth, err := auth.ExtractTokenMetadata(r)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		fmt.Println("unauthorized")
		return
	}
	userId, err := auth.FetchAuth(tokenAuth)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		fmt.Println("unauthorized")
		return
	}
	td.UserID = userId

	res, err := json.Marshal(td)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	rw.WriteHeader(http.StatusCreated)
	rw.Write(res)

	//Send the user a notification:
	msgResp, err := message.SendMessage(user.UserName, user.Phone)
	if err != nil {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("error occurred sending message to user"))
		return
	}
	if msgResp.StatusCode > 299 {
		rw.WriteHeader(http.StatusForbidden)
		rw.Write([]byte("cannot send message to user"))
		return
	}

	response, _ := json.Marshal(&td)
	rw.WriteHeader(http.StatusCreated)
	rw.Write(response)
}

// When a user logs out, we will instantly revoke/invalidate their JWT

func Logout(rw http.ResponseWriter, r *http.Request) {
	au, err := auth.ExtractTokenMetadata(r)
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("unauthorized"))
		return
	}
	deleted, delErr := auth.DeleteAuth(au.AccessUuid)
	if delErr != nil || deleted == 0 {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("unauthorized"))
		return
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Successfully logged out"))
}

func Refresh(rw http.ResponseWriter, r *http.Request) {
	refreshToken := auth.Token{}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	json.Unmarshal(body, &refreshToken)

	//Verify the token:
	os.Setenv("REFRESH_SECRET", "mcmvmkmsdnfsdmfdsjf") //this should be in an env file
	token, err := jwt.Parse(refreshToken.Refresh, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(os.Getenv("REFRESH_SECRET")), nil
	})
	if err != nil {
		rw.WriteHeader(http.StatusUnauthorized)
		rw.Write([]byte("Refresh token expired"))
		return
	}
	//Is token valid?
	if _, ok := token.Claims.(jwt.Claims); !ok && !token.Valid {
		rw.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims, ok := token.Claims.(jwt.MapClaims) //the token claims should conform to MapClaims
	if ok && token.Valid {
		refreshUuid, ok := claims["refresh_uuid"].(string) //convert the interface to string
		if !ok {
			rw.WriteHeader(http.StatusUnprocessableEntity)
			rw.Write([]byte(err.Error()))
			return
		}
		userId, err := strconv.ParseUint(fmt.Sprintf("%.f", claims["user_id"]), 10, 64)
		if err != nil {
			rw.WriteHeader(http.StatusUnprocessableEntity)
			rw.Write([]byte("Error occurred"))
			return
		}

		//Delete the previous Refresh Token:
		deleted, delErr := auth.DeleteAuth(refreshUuid)
		if delErr != nil || deleted == 0 { //if any goes wrong
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("unauthorized"))
			return
		}
		//Create new pairs of refresh and access tokens:
		ts, createErr := auth.CreateToken(userId)
		if createErr != nil {
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte(createErr.Error()))
			return
		}
		//Save the tokens metadata to redis:
		saveErr := auth.CreateAuth(userId, ts)
		if saveErr != nil {
			rw.WriteHeader(http.StatusForbidden)
			rw.Write([]byte(saveErr.Error()))
			return
		}
		tokens := map[string]string{
			"access_token":  ts.AccessToken,
			"refresh_token": ts.RefreshToken,
		}
		res, _ := json.Marshal(&tokens)

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusCreated)
		rw.Write(res)

	} else {
		rw.WriteHeader(http.StatusUnauthorized)

	}

}

func TokenAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		err := auth.TokenValid(r)
		if err != nil {
			rw.WriteHeader(http.StatusUnauthorized)
			rw.Write([]byte("this message is from the middleware."))
			return
		}
		next.ServeHTTP(rw, r)
	})
}
