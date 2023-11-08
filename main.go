package main

import (
	"github.com/gin-gonic/gin"
	"github.com/jmcerez0/gin-demo/handlers"
	"github.com/jmcerez0/gin-demo/middlewares"
	"github.com/jmcerez0/gin-demo/utils"
)

func init() {
	utils.LoadEnv()
	utils.CreateDB()
	utils.ConnectToDB()
	utils.MigrateSchema()
}

func main() {
	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "Hello World!",
		})
	})

	r.POST("/signup", handlers.SignUp)

	r.POST("/signin", handlers.SignIn)

	r.GET("/users", middlewares.RequireAuth, handlers.GetAllUsers)

	r.Run()
}
