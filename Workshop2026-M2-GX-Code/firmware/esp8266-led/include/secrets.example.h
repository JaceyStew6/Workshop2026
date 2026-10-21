// Copie générée par tools/make_firmware_config.py en include/secrets.h (NON versionné : contient le jeton de l'appareil
// et le mot de passe WiFi). Cette version d'exemple ne sert qu'à vérifier que le firmware compile.
#pragma once
#define WIFI_SSID "hotspot-resilience"
#define WIFI_PASS "changez-moi"
#define GATE_HOST "192.168.137.1"   // IP du PC Hôte sur le hotspot (celle du WAF, voir HOST_IP dans .env)
#define GATE_PORT 80
#define DEVICE_TOKEN "exemple-jeton-appareil"
