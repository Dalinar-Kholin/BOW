package main

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

func main() {
	router := gin.Default()

	router.GET("/getGraph", func(c *gin.Context) {
		c.JSON(http.StatusOK, GetGraph())
	})
	// Define a simple GET route
	router.GET("/getEncryptedGraph", func(c *gin.Context) {
		c.JSON(http.StatusOK, GetEncryptedGraph())
	})

	router.GET("/getColors", func(c *gin.Context) {
		sha := c.Request.URL.Query().Get("sha")
		id1Str := c.Request.URL.Query().Get("id1")
		id2Str := c.Request.URL.Query().Get("id2")

		id1, _ := strconv.Atoi(id1Str)
		id2, _ := strconv.Atoi(id2Str)

		c.JSON(http.StatusOK, GetColors(id1, id2, sha))
	})

	var wg sync.WaitGroup

	go func(wg *sync.WaitGroup) {
		wg.Add(1)
		router.Run(":8080")
	}(&wg)

	if err := waitForHTTP("http://127.0.0.1:8080/getGraph", 2*time.Second); err != nil {
		log.Fatal(err)
	}

	for range 10_000 {
		Verify()
	}
	wg.Wait()

}

func waitForHTTP(url string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		resp, err := http.Get(url)
		if err == nil && resp.StatusCode < 500 {
			_ = resp.Body.Close()
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return fmt.Errorf("service not healthy, status: %v", resp.Status)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
