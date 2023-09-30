package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       uint   `json:"id" gorm:"primary_key"`
	Username string `json:"username"`
	Password string `json:"-"`
}

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type Message struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Text      string             `bson:"text"`
	Timestamp time.Time          `bson:"timestamp"`
	UserID    uint               `bson:"user_id"`
}

var (
	db          *gorm.DB
	mongoClient *mongo.Client
	messageCol  *mongo.Collection
	upgrader    = websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin: func(r *http.Request) bool {
			return true
		},
	}
)

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Authorization header is missing"})
			c.Abort()
			return
		}

		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return []byte("your-secret-key"), nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token"})
			c.Abort()
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid token claims"})
			c.Abort()
			return
		}

		c.Set("user_id", claims["user_id"])
		c.Next()
	}
}

func Register(c *gin.Context) {
	var request RegisterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(request.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to hash password"})
		return
	}

	user := User{
		Username: request.Username,
		Password: string(hashedPassword),
	}

	db.Create(&user)
	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

func Login(c *gin.Context) {
	var request RegisterRequest
	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request"})
		return
	}

	var user User
	if err := db.Where("username = ?", request.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Invalid credentials"})
		return
	}

	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.ID

	tokenString, err := token.SignedString([]byte("your-secret-key"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

func main() {
	r := gin.Default()

	var err error
	db, err = gorm.Open("postgres", "postgresql://postgres:e9qQCfT1cwbd3P2ETfa3@containers-us-west-193.railway.app:7552/railway?sslmode=disable")
	if err != nil {
		panic("Failed to connect to database")
	}
	db.AutoMigrate(&User{})
	initMongoDB()
	initMongoCollections()
	defer db.Close()

	r.GET("/user", JWTMiddleware(), func(c *gin.Context) {
		id, _ := c.Get("user_id")
		var user User
		if err := db.Where("id = ?", id).First(&user).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"message": "User not found"})
			return
		}

		c.JSON(http.StatusOK, user)
	})

	r.POST("/register", Register)
	r.POST("/login", Login)

	r.GET("/ws", WebSocketHandler)

	r.Run(":8080")
}
func initMongoDB() {
	clientOptions := options.Client().ApplyURI("mongodb://mongo:6rBRMwd6S6bzM5LDXaSV@containers-us-west-208.railway.app:7798") // Update with your MongoDB URI
	client, err := mongo.Connect(context.Background(), clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// Ping the database to ensure the connection is established
	err = client.Ping(context.Background(), nil)
	if err != nil {
		log.Fatal(err)
	}

	mongoClient = client
	fmt.Println("Connected to MongoDB")
}

func initMongoCollections() {
	messageCol = mongoClient.Database("msg").Collection("msgs")
}

func StoreMessage(text string, userID uint) {
	message := Message{
		Text:      text,
		Timestamp: time.Now(),
		UserID:    userID,
	}

	_, err := messageCol.InsertOne(context.Background(), message)
	if err != nil {
		log.Println("Failed to store message in MongoDB:", err)
	}
}

// func WebSocketHandler(c *gin.Context) {
// 	// Upgrade the HTTP connection to a WebSocket connection
// 	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	defer conn.Close()

// 	// TODO: Implement WebSocket message handling here
// }

// func WebSocketHandler(c *gin.Context) {
// 	// Upgrade the HTTP connection to a WebSocket connection
// 	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
// 	if err != nil {
// 		log.Println(err)
// 		return
// 	}
// 	// defer conn.Close()

// 	// TODO: Implement WebSocket message handling here
// 	// userID := uint(1) // Replace with the actual user ID (you should implement user authentication)

// 	// Create a channel to manage WebSocket clients
// 	clients := make(map[*websocket.Conn]bool)
// 	broadcast := make(chan Message)

// 	// Register client
// 	clients[conn] = true

// 	// Handle incoming messages
// 	go func() {
// 		for {
// 			var msg Message
// 			err := conn.ReadJSON(&msg)
// 			if err != nil {
// 				log.Println(err)
// 				delete(clients, conn)
// 				return
// 			}
// 			// msg.UserID = userID

// 			// Store the message in MongoDB
// 			StoreMessage(msg.Text, msg.UserID)

// 			// Broadcast the message to all connected clients
// 			broadcast <- msg
// 		}
// 	}()

// 	// Send messages to clients
// 	go func() {
// 		for {
// 			msg := <-broadcast
// 			for client := range clients {
// 				err := client.WriteJSON(msg)
// 				if err != nil {
// 					log.Println(err)
// 					client.Close()
// 					delete(clients, client)
// 				}
// 			}
// 		}
// 	}()
// }

func WebSocketHandler(c *gin.Context) {
	// Upgrade the HTTP connection to a WebSocket connection
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Println(err)
		return
	}
	defer conn.Close()

	// Read the token from the WebSocket message
	_, tokenMessage, err := conn.ReadMessage()
	if err != nil {
		log.Println(err)
		return
	}

	// Validate the token in tokenMessage (assuming it's a JWT token)
	tokenString := string(tokenMessage)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Replace with your actual secret key for JWT validation
		return []byte("your-secret-key"), nil
	})

	if err != nil || !token.Valid {
		log.Println("Invalid JWT token in WebSocket connection:", err)
		return
	}

	// The WebSocket connection is authenticated and can proceed
	for {
		// Handle WebSocket messages here
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println(err)
			break
		}

		// Process and respond to WebSocket messages
		// For example, echoing the received message back to the client:
		if err := conn.WriteMessage(messageType, p); err != nil {
			log.Println(err)
			break
		}
	}
}
