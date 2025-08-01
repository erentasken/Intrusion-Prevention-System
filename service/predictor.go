package service

import (
	"encoding/json"
	"fmt"
	"net"
	"time"
)

func getPrediction(dataString []string) (string, error) {
	// Connect to the Python server over TCP
	conn, err := net.Dial("tcp", "172.30.0.11:50051")
	if err != nil {
		return "", fmt.Errorf("failed to connect to server: %v", err)
	}
	defer conn.Close()

	// Serialize data using JSON
	data, err := json.Marshal(dataString)
	if err != nil {
		return "", fmt.Errorf("failed to encode data: %v", err)
	}

	// Send the serialized data to the server
	_, err = conn.Write(data)
	if err != nil {
		return "", fmt.Errorf("failed to send data: %v", err)
	}

	// Set a timeout to read the response
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))

	// Receive predictions from the server
	resp := make([]byte, 4096)
	n, err := conn.Read(resp)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	// Deserialize the response
	var predictions []int
	err = json.Unmarshal(resp[:n], &predictions)
	if err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	model_names := []string{
		"logistic_regression", "lightgbm", 
		"random_forest", "xgboost", "gradient_boosting", 
		"svm", "knn", "naïve_bayes", "catboost", "nn",
	}

	var predictionString string
	for i, v := range model_names {
		predictionString += fmt.Sprintf("%s: %d  ", v, predictions[i])
	}

	return predictionString, nil
}
