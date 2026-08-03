package flag

import (
	"net/url"
)

func IsHTTPURL(path string) bool {
	u, err := url.Parse(path)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func OneOf(image, repo, imageFile string) bool {
	return (image != "" && repo == "" && imageFile == "") ||
		(image == "" && repo != "" && imageFile == "") ||
		(image == "" && repo == "" && imageFile != "")
}
