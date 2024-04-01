package main

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"net/http"
	"os"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/api/types/swarm"

	"github.com/docker/docker/client"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type serviceInfoType struct {
	ServiceID string
	ImageName string
	AuthToken string
}

type containerInfoType struct {
	ContainerID   string
	ContainerName string
	ImageName     string
	AuthToken     string
}

var registeredServices = make(map[string]serviceInfoType)
var registeredContainers = make(map[string]containerInfoType)

const registrationFile = "/app/registrations/registrations.json"

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	e := echo.New()

	e.POST("/webhook/:uuid", handleWebhook)
	e.GET("/containers", getContainers)

	loadRegistrations()
	printRegistrations()

	go watchServices()

	port := os.Getenv("PORT")
	if port == "" {
		port = "8000"
	}

	log.Info().Msgf("Starting server on port %s", port)
	e.Logger.Fatal(e.Start(":" + port))
}

func handleWebhook(c echo.Context) error {
	uuid := c.Param("uuid")

	service, ok := registeredServices[uuid]
	if ok {
		imageName := service.ImageName
		authToken := service.AuthToken

		log.Info().Msgf("Updating service with UUID: %s, Image: %s", uuid, imageName)
		err := updateService(imageName, authToken)
		if err != nil {
			log.Error().Msgf("Error updating service with UUID: %s, Error: %s", uuid, err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		log.Info().Msgf("Service updated successfully for UUID: %s", uuid)
		return c.JSON(http.StatusOK, map[string]string{"message": "Webhook received and service updated successfully"})
	}

	container, ok := registeredContainers[uuid]
	if ok {
		imageName := container.ImageName
		authToken := container.AuthToken
		containerID := container.ContainerID
		containerName := container.ContainerName

		log.Info().Msgf("Updating container with UUID: %s, Image: %s", uuid, imageName)
		err := updateContainer(containerID, containerName, imageName, authToken)
		if err != nil {
			log.Error().Msgf("Error updating container with UUID: %s, Error: %s", uuid, err)
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}

		log.Info().Msgf("Container updated successfully for UUID: %s", uuid)
		return c.JSON(http.StatusOK, map[string]string{"message": "Webhook received and container updated successfully"})
	}

	log.Error().Msgf("Service or container not found for UUID: %s", uuid)
	return c.JSON(http.StatusNotFound, map[string]string{"error": "Service or container not found"})
}

func getContainers(c echo.Context) error {
	containers := make(map[string]string)
	for uuid, container := range registeredContainers {
		containers[container.ContainerName] = uuid
	}
	return c.JSON(http.StatusOK, containers)
}

func updateContainer(containerID, containerName, imageName, authToken string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	// Find the UUID associated with the container ID
	var uuid string
	for id, container := range registeredContainers {
		if container.ContainerID == containerID {
			uuid = id
			break
		}
	}

	if uuid == "" {
		// Container not found in the registration, generate a new UUID
		uuid = generateUUID()
	}

	// Inspect the existing container
	containerInfo, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return err
	}

	// Pull the latest image
	registryAuth := getRegistryAuth(authToken)
	log.Info().Msgf("Pulling the latest image: %s", imageName)
	_, err = cli.ImagePull(ctx, imageName, types.ImagePullOptions{RegistryAuth: registryAuth})
	if err != nil {
		return err
	}

	// Stop the existing container
	log.Info().Msgf("Stopping container: %s", containerID)
	err = cli.ContainerStop(ctx, containerID, container.StopOptions{})
	if err != nil {
		return err
	}

	// Remove the existing container
	log.Info().Msgf("Removing container: %s", containerID)
	err = cli.ContainerRemove(ctx, containerID, container.RemoveOptions{})
	if err != nil {
		return err
	}

	// Create a new container with the updated image and original configuration
	log.Info().Msgf("Creating new container with image: %s", imageName)
	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        imageName,
		Env:          containerInfo.Config.Env,
		ExposedPorts: containerInfo.Config.ExposedPorts,
		Labels:       containerInfo.Config.Labels,
		// Set other relevant configuration fields from the original container
	}, &container.HostConfig{
		Binds:         containerInfo.HostConfig.Binds,
		PortBindings:  containerInfo.HostConfig.PortBindings,
		RestartPolicy: containerInfo.HostConfig.RestartPolicy,
		// Set other relevant host configuration fields from the original container
	}, nil, nil, "")
	if err != nil {
		return err
	}

	// Start the new container
	log.Info().Msgf("Starting new container: %s", resp.ID)
	err = cli.ContainerStart(ctx, resp.ID, container.StartOptions{})
	if err != nil {
		return err
	}

	// Update the registered container with the new container ID and image name
	registeredContainers[uuid] = containerInfoType{
		ContainerID:   resp.ID,
		ContainerName: containerName,
		ImageName:     imageName,
		AuthToken:     authToken,
	}

	log.Info().Msgf("Container updated successfully: %s, UUID: %s", resp.ID, uuid)
	return nil
}

func watchServices() {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		log.Error().Msgf("Error creating Docker client: %s", err)
		return
	}
	defer cli.Close()

	serviceFilter := filters.NewArgs()
	serviceFilter.Add("label", "webhook.enable=true")

	serviceOptions := types.ServiceListOptions{
		Filters: serviceFilter,
	}

	containerFilter := filters.NewArgs()
	containerFilter.Add("label", "webhook.enable=true")

	containerOptions := container.ListOptions{
		Filters: containerFilter,
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		services, err := cli.ServiceList(ctx, serviceOptions)
		if err != nil {
			log.Error().Msgf("Error listing services: %s", err)
		} else {
			for _, service := range services {
				registerService(service.ID, service.Spec)
			}
		}

		containers, err := cli.ContainerList(ctx, containerOptions)
		if err != nil {
			log.Error().Msgf("Error listing containers: %s", err)
		} else {
			runningContainers := make(map[string]bool)
			for _, container := range containers {
				runningContainers[container.ID] = true
				registerContainer(container.ID, container.Names[0], container.Labels, container.Image)
			}

			// Remove registered containers that no longer exist
			for uuid, container := range registeredContainers {
				if !runningContainers[container.ContainerID] {
					delete(registeredContainers, uuid)
					log.Info().Msgf("Removed non-existent container from registration: %s", container.ContainerID)
				}
			}
		}

		saveRegistrations()
		printRegistrations()
	}
}

func saveRegistrations() {
	data := map[string]interface{}{
		"services":   registeredServices,
		"containers": registeredContainers,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Error().Msgf("Error marshaling registrations: %s", err)
		return
	}

	err = os.WriteFile(registrationFile, jsonData, 0644)
	if err != nil {
		log.Error().Msgf("Error saving registrations: %s", err)
	}
}

func loadRegistrations() {
	if _, err := os.Stat(registrationFile); os.IsNotExist(err) {
		// Registration file doesn't exist, start with empty registrations
		registeredServices = make(map[string]serviceInfoType)
		registeredContainers = make(map[string]containerInfoType)
		return
	}

	data, err := os.ReadFile(registrationFile)
	if err != nil {
		log.Error().Msgf("Error reading registrations file: %s", err)
		return
	}

	var registrations map[string]interface{}
	err = json.Unmarshal(data, &registrations)
	if err != nil {
		log.Error().Msgf("Error unmarshaling registrations: %s", err)
		return
	}

	registeredServices = make(map[string]serviceInfoType)
	for uuid, info := range registrations["services"].(map[string]interface{}) {
		registeredServices[uuid] = serviceInfoType{
			ServiceID: info.(map[string]interface{})["ServiceID"].(string),
			ImageName: info.(map[string]interface{})["ImageName"].(string),
			AuthToken: info.(map[string]interface{})["AuthToken"].(string),
		}
	}

	registeredContainers = make(map[string]containerInfoType)
	for uuid, info := range registrations["containers"].(map[string]interface{}) {
		registeredContainers[uuid] = containerInfoType{
			ContainerID: info.(map[string]interface{})["ContainerID"].(string),
			ImageName:   info.(map[string]interface{})["ImageName"].(string),
			AuthToken:   info.(map[string]interface{})["AuthToken"].(string),
		}
	}
}

func registerService(serviceID string, serviceSpec swarm.ServiceSpec) {
	imageName := serviceSpec.TaskTemplate.ContainerSpec.Image
	authToken := serviceSpec.Labels["webhook.auth_token"]

	uuid := generateUUID()
	registeredServices[uuid] = serviceInfoType{
		ServiceID: serviceID,
		ImageName: imageName,
		AuthToken: authToken,
	}
	log.Info().Msgf("Registered service: %s, UUID: %s, Image: %s", serviceID, uuid, imageName)
}

func registerContainer(containerID string, containerName string, labels map[string]string, imageName string) {
	authToken := labels["webhook.auth_token"]

	// Check if the container is already registered
	for uuid, container := range registeredContainers {
		if container.ContainerID == containerID {
			// Container already registered, update the image name and auth token if needed
			container.ImageName = imageName
			container.ContainerName = containerName
			container.AuthToken = authToken
			registeredContainers[uuid] = container
			log.Info().Msgf("Updated registered container: %s, Image: %s", containerID, imageName)
			return
		}
	}

	// Container not registered, generate a new UUID and add it to the map
	uuid := generateUUID()
	registeredContainers[uuid] = containerInfoType{
		ContainerID:   containerID,
		ContainerName: containerName,
		ImageName:     imageName,
		AuthToken:     authToken,
	}
	log.Info().Msgf("Registered new container: %s, UUID: %s, Image: %s", containerID, uuid, imageName)
}

func generateUUID() string {
	return uuid.New().String()
}

func updateService(imageName, authToken string) error {
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return err
	}
	defer cli.Close()

	registryAuth := getRegistryAuth(authToken)

	log.Info().Msgf("Pulling the latest image: %s", imageName)
	_, err = cli.ImagePull(ctx, imageName, types.ImagePullOptions{RegistryAuth: registryAuth})
	if err != nil {
		return err
	}

	log.Info().Msgf("Image %s pulled successfully", imageName)
	return nil
}

func getRegistryAuth(authToken string) string {
	if authToken == "" {
		return ""
	}

	authConfig := registry.AuthConfig{
		Username: "oauth2accesstoken",
		Password: authToken,
	}
	encodedJSON, _ := json.Marshal(authConfig)
	return base64.StdEncoding.EncodeToString(encodedJSON)
}

func printRegistrations() {
	log.Info().Msg("Registered Services:")
	if len(registeredServices) == 0 {
		log.Info().Msg("  No services registered")
	} else {
		for uuid, service := range registeredServices {
			log.Info().Msgf("  UUID: %s", uuid)
			log.Info().Msgf("    Service ID: %s", service.ServiceID)
			log.Info().Msgf("    Image Name: %s", service.ImageName)
			log.Info().Msgf("    Auth Token: %s", service.AuthToken)
			log.Info().Msg("")
		}
	}

	log.Info().Msg("Registered Containers:")
	if len(registeredContainers) == 0 {
		log.Info().Msg("  No containers registered")
	} else {
		for uuid, container := range registeredContainers {
			log.Info().Msgf("  UUID: %s", uuid)
			log.Info().Msgf("    Container ID: %s", container.ContainerID)
			log.Info().Msgf("    Container Name: %s", container.ContainerName)
			log.Info().Msgf("    Image Name: %s", container.ImageName)
			log.Info().Msgf("    Auth Token: %s", container.AuthToken)
			log.Info().Msg("")
		}
	}
}
