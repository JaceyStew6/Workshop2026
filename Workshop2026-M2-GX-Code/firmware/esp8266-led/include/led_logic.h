// Logique du voyant, SANS dépendance à Arduino : compilable et testable sur le PC (voir test/).
// Le serveur (face-gate) reste maître : il envoie {seq, pattern, remaining_ms}. L'ESP reproduit le motif localement
// (clignotement 1 Hz) et s'éteint tout seul à l'échéance, ou si le serveur ne répond plus (échec sûr : jamais de LED
// verte « périmée » qui laisserait croire à un accès ouvert).
#pragma once
#include <stdint.h>
#include <string.h>

enum class Pattern : uint8_t { Off, GreenBlink, GreenSolid, RedBlink, RedSolid };

inline Pattern parse_pattern(const char* s) {
  if (!s) return Pattern::Off;
  if (strcmp(s, "green_blink") == 0) return Pattern::GreenBlink;
  if (strcmp(s, "green_solid") == 0) return Pattern::GreenSolid;
  if (strcmp(s, "red_blink") == 0) return Pattern::RedBlink;
  if (strcmp(s, "red_solid") == 0) return Pattern::RedSolid;
  return Pattern::Off;  // motif inconnu : éteint
}

struct LedOutputs {
  bool green;
  bool red;
};

class LedLogic {
 public:
  static constexpr uint32_t kBlinkHalfPeriodMs = 500;  // 1 Hz : 10 s de « rouge clignotant » = 10 clignotements
  static constexpr uint32_t kFailSafeMs = 5000;        // sans réponse valide depuis 5 s : éteint

  // À appeler à chaque réponse valide du serveur (now = millis()).
  void on_answer(uint32_t seq, Pattern p, uint32_t remaining_ms, uint32_t now) {
    last_ok_ = now;
    have_ok_ = true;
    if (p == Pattern::Off) {
      pattern_ = Pattern::Off;
      seq_ = seq;
      return;
    }
    if (seq != seq_ || p != pattern_) {  // nouvel épisode : la phase du clignotement repart de zéro (allumé d'abord)
      start_ = now;
      pattern_ = p;
      seq_ = seq;
    }
    until_ = now + remaining_ms;  // recale l'échéance sur l'horloge du serveur
  }

  LedOutputs outputs(uint32_t now) const {
    if (!have_ok_ || static_cast<uint32_t>(now - last_ok_) > kFailSafeMs) return {false, false};
    if (pattern_ == Pattern::Off || static_cast<int32_t>(now - until_) >= 0) return {false, false};
    const bool solid = pattern_ == Pattern::GreenSolid || pattern_ == Pattern::RedSolid;
    const bool on = solid || (((now - start_) / kBlinkHalfPeriodMs) % 2 == 0);
    const bool green = pattern_ == Pattern::GreenBlink || pattern_ == Pattern::GreenSolid;
    return {on && green, on && !green};
  }

 private:
  uint32_t seq_ = 0, start_ = 0, until_ = 0, last_ok_ = 0;
  Pattern pattern_ = Pattern::Off;
  bool have_ok_ = false;
};
