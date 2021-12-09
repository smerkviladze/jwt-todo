package models

type User struct {
	ID       uint64 `json:"id"`
	UserName string `json:"user_name"`
	Password string `json:"password"`
	Phone    string `json:"phone"`
}

type Todo struct {
	UserID uint64 `jason:"user_id"`
	Title  string `jason:"title"`
}

// Extract the token metadata that will lookup in Redis store
// First we need to create a new struct. This struct contains the metadata (access_uuid and user_id) that we will need to make a lookup in Redis.
type AccessDetails struct {
	AccessUuid string
	UserId     uint64
}
