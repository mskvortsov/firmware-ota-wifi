#include <string.h>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "mbedtls/md5.h"

#include "lwip/err.h"
#include "lwip/sys.h"
#include "lwip/sockets.h"

#define TAG "OTA"
#define INFO(format, ...) do { printf(TAG " I " format "\r\n", ##__VA_ARGS__); } while (0)
#define WARN(format, ...) do { printf(TAG " W " format "\r\n", ##__VA_ARGS__); } while (0)
#define FAIL(format, ...) do { printf(TAG " F " format "\r\n", ##__VA_ARGS__); esp_restart(); } while (0)

typedef struct {
    char ssid[32];
    char psk[64];
} wifi_credentials_t;

static nvs_handle_t s_nvs_handle;

static void nvs_init(const char *namespace)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(nvs_open(namespace, NVS_READWRITE, &s_nvs_handle));
}

static void nvs_read_config(wifi_credentials_t *config)
{
    size_t ssid_len = sizeof(config->ssid);
    size_t psk_len = sizeof(config->psk);
    ESP_ERROR_CHECK(nvs_get_str(s_nvs_handle, "ssid", config->ssid, &ssid_len));
    ESP_ERROR_CHECK(nvs_get_str(s_nvs_handle, "psk", config->psk, &psk_len));
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs_handle, "updated", 0));
    ESP_ERROR_CHECK(nvs_commit(s_nvs_handle));
}

static void nvs_mark_updated()
{
    ESP_ERROR_CHECK(nvs_set_u8(s_nvs_handle, "updated", 1));
    ESP_ERROR_CHECK(nvs_commit(s_nvs_handle));
    nvs_close(s_nvs_handle);
}

static const int wifi_connect_retries = 10;
static const EventBits_t BIT_CONNECTED = BIT0;
static const EventBits_t BIT_FAIL = BIT1;
static EventGroupHandle_t event_group_handle;

static void event_handler(void* arg, esp_event_base_t event_base,
                          int32_t event_id, void* event_data)
{
    static int s_retry_num = 0;
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            if (s_retry_num < wifi_connect_retries) {
                esp_wifi_connect();
                ++s_retry_num;
            } else {
                xEventGroupSetBits(event_group_handle, BIT_FAIL);
            }
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            s_retry_num = 0;
            xEventGroupSetBits(event_group_handle, BIT_CONNECTED);
        }
    } else {
        FAIL("Unknown event");
    }
}

static void wifi_connect(const wifi_credentials_t *config)
{
    event_group_handle = xEventGroupCreate();

    ESP_ERROR_CHECK(esp_netif_init());

    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t instance_any_id;
    esp_event_handler_instance_t instance_got_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &event_handler, NULL, &instance_any_id));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &event_handler, NULL, &instance_got_ip));

    wifi_config_t wifi_config = {
        .sta.threshold.authmode = WIFI_AUTH_WPA_PSK,
    };
    strncpy(wifi_config.sta.ssid, config->ssid, sizeof(wifi_config.sta.ssid));
    strncpy(wifi_config.sta.password, config->psk, sizeof(wifi_config.sta.password));

    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(event_group_handle,
        BIT_CONNECTED | BIT_FAIL, pdFALSE, pdFALSE, portMAX_DELAY);

    if (!(bits & BIT_CONNECTED)) {
        FAIL("Failed to connect to WiFi AP");
    }
}

typedef struct {
    in_port_t remote_port;
    struct sockaddr_in remote_ctrl_addr;
    size_t firmware_size;
    uint8_t firmware_md5[16];
} ota_config_t;

#define OK "OK"
#define OK_LEN 2
static char buffer[1024];

static bool md5_string_to_bytes(const char *hex, uint8_t *bytes)
{
    for (int i = 0; i < 16; ++i) {
        unsigned int byte = 0;
        if (sscanf(&hex[i * 2], "%02x", &byte) != 1) {
            return false;
        }
        bytes[i] = (uint8_t)byte;
    }
    return true;
}

static void ota_parse_config(const char *buffer, ota_config_t *config)
{
    int command = 0;
    unsigned int remote_port = 0;
    unsigned int firmware_size = 0;
    char md5[33] = { 0 };
    int res = sscanf((const char *)buffer, "%d %u %u %32s", &command, &remote_port, &firmware_size, &md5);
    if (res != 4) {
        FAIL("Invalid header");
    }
    if (command != 0) {
        FAIL("Invalid command");
    }
    if (remote_port > UINT16_MAX) {
        FAIL("Invalid port");
    }
    if (firmware_size > 8 * 1024 * 1024) {
        FAIL("Invalid firmware size");
    }
    uint8_t md5_bytes[16];
    if (!md5_string_to_bytes(md5, md5_bytes)) {
        FAIL("Invalid MD5 string");
    }

    config->remote_port = htons(remote_port);
    config->firmware_size = firmware_size;
    memcpy(config->firmware_md5, md5_bytes, sizeof(md5_bytes));
}

static int ota_bind_ctrl(int port)
{
    struct sockaddr_in ctrl_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {
            .s_addr = INADDR_ANY,
        },
    };
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        FAIL("Failed to create socket");
    }
    struct timeval timeout = { 0 };
    timeout.tv_sec = 120;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        FAIL("Failed to set timeout");
    }
    if (bind(sock, (const struct sockaddr *)&ctrl_addr, sizeof(struct sockaddr_in)) < 0) {
        FAIL("Failed to bind socket");
    }
    return sock;
}

static int ota_receive_config(int port, ota_config_t *config)
{
    int sock_ctrl = ota_bind_ctrl(port);

    struct sockaddr_in source_addr;
    socklen_t source_addr_len = sizeof(struct sockaddr_in);
    ssize_t len = recvfrom(sock_ctrl, buffer, sizeof(buffer), 0, (struct sockaddr *)&source_addr, &source_addr_len);
    if (len < 0) {
        FAIL("Failed to receive invitation");
    }

    ota_parse_config(buffer, config);
    config->remote_ctrl_addr = source_addr;

    return sock_ctrl;
}

static int ota_connect_data(ota_config_t *config)
{
    struct sockaddr_in data_addr;
    data_addr.sin_family = AF_INET;
    data_addr.sin_addr.s_addr = config->remote_ctrl_addr.sin_addr.s_addr;
    data_addr.sin_port = config->remote_port;

    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    if (sock < 0) {
        FAIL("Failed to create socket");
    }
    int res = connect(sock, (const struct sockaddr *)&data_addr, sizeof(data_addr));
    if (res != 0) {
        return -1;
    }
    return sock;
}

static void ota_flash()
{
    INFO("Waiting for invitation");
    ota_config_t config;
    int sock_ctrl = ota_receive_config(3232, &config);
    INFO("Received invitation");

    const esp_partition_t *part_firmware = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_0, NULL);
    const esp_partition_t *part_ota = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_1, NULL);

    INFO("Erasing flash");
    esp_ota_handle_t ota_handle;
    ESP_ERROR_CHECK(esp_ota_begin(part_firmware, OTA_SIZE_UNKNOWN, &ota_handle));
    ESP_ERROR_CHECK(esp_ota_set_boot_partition(part_ota));

    mbedtls_md5_context md5_context;
    mbedtls_md5_init(&md5_context);

    int sock = -1;
    int connect_retries = 5;
    do {
        INFO("Confirming invitation");
        if (sendto(sock_ctrl, OK, OK_LEN, 0, (const struct sockaddr *)&config.remote_ctrl_addr, sizeof(struct sockaddr_in)) != OK_LEN) {
            FAIL("Failed to send invitation confirmation");
        }
        vTaskDelay(200 / portTICK_PERIOD_MS);
        INFO("Connecting to host");
        sock = ota_connect_data(&config);
    } while (--connect_retries && sock < 0);
    if (sock < 0) {
        INFO("Failed to connect to host");
    }
    INFO("Connected to host, now flashing");
    closesocket(sock_ctrl);

    size_t bytes_received = 0;
    while (bytes_received < config.firmware_size) {
        size_t len = recv(sock, buffer, sizeof(buffer), 0);
        if (len < 0) {
            FAIL("Failed to receive a chunk");
        }
        mbedtls_md5_update(&md5_context, buffer, len);
        ESP_ERROR_CHECK(esp_ota_write(ota_handle, buffer, len));
        if (send(sock, OK, OK_LEN, 0) != OK_LEN) {
            FAIL("Failed to confirm a chunk");
        }
        bytes_received += len;
    }

    ESP_ERROR_CHECK(esp_ota_end(ota_handle));

    shutdown(sock, 0);
    closesocket(sock);

    INFO("Firmware received");
    unsigned char md5[16];
    mbedtls_md5_finish(&md5_context, md5);
    if (memcmp(config.firmware_md5, md5, sizeof(md5)) != 0) {
        FAIL("Checksum mismatch");
    }

    INFO("Checksum OK");
    ESP_ERROR_CHECK(esp_ota_set_boot_partition(part_firmware));
}

void app_main()
{
    const esp_app_desc_t *desc = esp_app_get_description();
    printf("%s %s %s %s %s\r\n", desc->project_name, desc->version,
        desc->idf_ver, desc->date, desc->time);

    nvs_init("ota-wifi");
    wifi_credentials_t config;
    INFO("Reading NVRAM storage");
    nvs_read_config(&config);

    INFO("Connecting to WiFi AP \"%s\"", config.ssid);
    wifi_connect(&config);

    ota_flash();
    nvs_mark_updated();

    INFO("Success, rebooting to updated firmware");
    esp_restart();
}
