package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
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
	broadcast   = make(chan Message)
	upgrader    = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// Check origin to prevent WebSocket hijacking
			return true
		},
	}

	// Maintain a list of connected clients.
	clients = make(map[*websocket.Conn]bool)
	mutex   sync.Mutex
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

func initMongoDB() {
	clientOptions := options.Client().ApplyURI("mongodb://mongo:p5DqtCP4sd2psY7qvpzz@containers-us-west-136.railway.app:6055") // Update with your MongoDB URI
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
		ID:        primitive.NewObjectID(), // Generate a new ObjectID
		Text:      text,
		Timestamp: time.Now(),
		UserID:    userID,
	}

	fmt.Println(message)
	_, err := messageCol.InsertOne(context.Background(), message)
	if err != nil {
		log.Println("Failed to store message in MongoDB:", err)
	}
}

// Broadcast a message to all connected clients.
// func broadcastMessage(message []byte) {
// 	mutex.Lock()
// 	defer mutex.Unlock()

//		for conn := range clients {
//			if err := conn.WriteMessage(websocket.TextMessage, message); err != nil {
//				// Handle any errors that occur while sending the message.
//				// You may want to remove the client from the list if an error occurs.
//				conn.Close()
//				delete(clients, conn)
//			}
//		}
//	}
func handleBroadcast() {
	for {
		message := <-broadcast
		for client := range clients {
			// Send the message to all connected clients.
			err := client.WriteJSON(message)
			if err != nil {
				log.Println("Error broadcasting message:", err)
				// Remove the client from the list of clients if there's an error.
				delete(clients, client)
				client.Close()
			}
		}
	}
}
func main() {
	r := gin.Default()
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"*"} // You can specify the allowed origins here. "*" allows all origins.
	config.AllowMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"}

	r.Use(cors.New(config))
	var err error
	db, err = gorm.Open("postgres", "postgresql://postgres:VhdLOGcRBFAHk0lX2Jo5@containers-us-west-47.railway.app:7110/railway?sslmode=disable")
	if err != nil {
		panic("Failed to connect to database")
	}
	db.AutoMigrate(&User{})
	initMongoDB()
	initMongoCollections()
	defer db.Close()

	r.GET("/messages", JWTMiddleware(), func(c *gin.Context) {
		user, _ := c.Get("user_id")
		options := options.Find()
		cursor, err := messageCol.Find(context.Background(), options)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to retrieve messages"})
			return
		}
		defer cursor.Close(context.Background())

		var messages []Message
		for cursor.Next(context.Background()) {
			var message Message
			if err := cursor.Decode(&message); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode message"})
				return
			}
			messages = append(messages, message)
		}

		c.JSON(http.StatusOK, gin.H{"msg": messages, "userId": user})
	})

	r.POST("/register", Register)
	r.POST("/login", Login)

	r.GET("/ws", func(c *gin.Context) {
		conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		defer conn.Close()

		// Add the new client to the list of clients.
		mutex.Lock()
		clients[conn] = true
		mutex.Unlock()

		// Handle incoming messages from clients
		go func() {
			for {
				var msg Message
				err := conn.ReadJSON(&msg)
				if err != nil {
					log.Println(err)
					return
				}

				StoreMessage(msg.Text, msg.UserID)

				// Broadcast the message to all connected clients
				// broadcast <- msg
			}
		}()

		for {
			var msg Message
			err := conn.ReadJSON(&msg)
			if err != nil {
				// Remove the client from the list of clients.
				mutex.Lock()
				delete(clients, conn)
				mutex.Unlock()
				break
			}

			// Handle incoming messages and store them in MongoDB
			StoreMessage(msg.Text, msg.UserID)
			// fmt.Print(p)

			// For demonstration, we'll simply broadcast the message to all connected clients.
			// broadcastMessage(p)
			broadcast <- msg
		}
	})
	go handleBroadcast()

	r.Run(":8080")
}
