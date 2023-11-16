package handlers

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/jmcerez0/gin-demo/models"
	"github.com/jmcerez0/gin-demo/utils"
)

func SignUp(c *gin.Context) {
	var body struct {
		FirstName string `form:"first_name" json:"first_name" xml:"first_name"  binding:"required"`
		LastName  string `form:"last_name" json:"last_name" xml:"last_name"  binding:"required"`
		Email     string `form:"email" json:"email" xml:"email"  binding:"required,email"`
		Password  string `form:"password" json:"password" xml:"password"  binding:"required,min=8"`
	}

	if err := c.Bind(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": err.Error(),
		})

		return
	}

	hashedPassword, err := utils.HashPassword(body.Password)

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
		Password:  hashedPassword,
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
		Email    string `form:"email" json:"email" xml:"email"  binding:"required,email"`
		Password string `form:"password" json:"password" xml:"password"  binding:"required"`
	}

	if err := c.Bind(&body); err != nil {
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

	if err := utils.ComparePassword(user.Password, body.Password); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Incorrect email or password.",
		})

		return
	}

	token, err := utils.GetToken(user)

	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
		})

		return
	}

	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("token", token, 3600*24*3, "", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"token": token,
	})
}

func GetAllUsers(c *gin.Context) {
	var users []models.User
	utils.DB.Find(&users)

	c.JSON(http.StatusOK, gin.H{
		"users": users,
	})
}
