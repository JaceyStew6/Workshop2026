#!/bin/sh
# Compile et exécute les tests de la logique du voyant sur le PC (g++ requis ; sous Windows : WSL).
set -eu
cd "$(dirname "$0")"
g++ -std=c++17 -Wall -Wextra -Werror -o /tmp/test_led_logic test_led_logic.cpp
/tmp/test_led_logic
