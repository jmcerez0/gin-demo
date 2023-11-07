package handlers

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jmcerez0/gin-demo/models"
	"github.com/jmcerez0/gin-demo/utils"
	"golang.org/x/crypto/bcrypt"
)

var err error

func SignUp(c *gin.Context) {
	var body struct {
		FirstName string
		LastName  string
		Email     string
		Password  string
	}

	err = c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})

		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), 10)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
		})

		return
	}

	user := models.User{
		FirstName: body.FirstName,
		LastName:  body.LastName,
		Email:     body.Email,
		Password:  string(hash),
	}

	result := utils.DB.Create(&user)

	if result.Error != nil {
		if strings.Contains(result.Error.Error(), "Error 1062 (23000)") {
			c.JSON(http.StatusConflict, gin.H{
				"message": result.Error.Error(),
			})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{
				"message": result.Error.Error(),
			})
		}

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User created successfully.",
	})
}

func SignIn(c *gin.Context) {
	var body struct {
		Email    string
		Password string
	}

	err = c.Bind(&body)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})

		return
	}

	var user models.User
	utils.DB.First(&user, "email = ?", body.Email)

	if user.ID == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Incorrect email or password.",
		})

		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(body.Password))

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Incorrect email or password.",
		})

		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub":  user.ID,
		"name": user.FirstName + " " + user.LastName,
		"iat":  time.Now().Unix(),
		"exp":  time.Now().Add(time.Hour * 24 * 3).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": err.Error(),
		})

		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", tokenString, 3600*24*3, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	utils.DB.Find(&users)

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}
