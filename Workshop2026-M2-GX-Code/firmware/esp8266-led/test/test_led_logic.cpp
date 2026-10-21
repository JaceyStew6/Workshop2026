// Test hôte (sans matériel) de la logique du voyant :  sh test/run-tests.sh
#include <cstdio>
#include <cstdlib>

#include "../include/led_logic.h"

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { std::printf("ECHEC ligne %d : %s\n", __LINE__, #cond); ++failures; } } while (0)

static LedOutputs at(const LedLogic& l, uint32_t t) { return l.outputs(t); }

int main() {
  {  // éteinte par défaut, avant toute réponse du serveur
    LedLogic l;
    CHECK(!at(l, 0).green && !at(l, 0).red && !at(l, 99999).green);
  }
  {  // vert clignotant tant que le serveur le demande, 1 Hz, allumé d'abord
    LedLogic l;
    l.on_answer(1, Pattern::GreenBlink, 119000, 1000);
    CHECK(at(l, 1000).green && !at(l, 1000).red);
    CHECK(at(l, 1499).green);
    CHECK(!at(l, 1500).green && !at(l, 1999).green);
    CHECK(at(l, 2000).green);
    for (uint32_t t = 2000; t < 60000; t += 1000) l.on_answer(1, Pattern::GreenBlink, 119000 - (t - 1000), t);
    CHECK(at(l, 60000).green);  // la phase n'a pas été remise à zéro par les réponses suivantes (même seq)
  }
  {  // vert fixe 30 s, puis extinction sûre si le serveur ne répond plus
    LedLogic l;
    l.on_answer(2, Pattern::GreenSolid, 30000, 0);
    CHECK(at(l, 100).green && !at(l, 100).red);
    for (uint32_t t = 1000; t <= 4000; t += 1000) l.on_answer(2, Pattern::GreenSolid, 30000 - t, t);
    CHECK(at(l, 4500).green);
    CHECK(at(l, 4000 + LedLogic::kFailSafeMs).green);
    CHECK(!at(l, 4000 + LedLogic::kFailSafeMs + 1).green);
  }
  {  // vert fixe : s'éteint à l'échéance (30 s) quand le serveur répond normalement
    LedLogic l;
    bool on_at_29900 = false, on_at_30000 = true, on_at_30500 = true;
    for (uint32_t t = 0; t <= 31000; t += 100) {
      if (t % 1000 == 0) l.on_answer(2, Pattern::GreenSolid, t < 30000 ? 30000 - t : 0, t);   // le serveur sonde chaque seconde
      if (t == 29900) on_at_29900 = at(l, t).green;
      if (t == 30000) on_at_30000 = at(l, t).green;
      if (t == 30500) on_at_30500 = at(l, t).green;
    }
    CHECK(on_at_29900);
    CHECK(!on_at_30000 && !on_at_30500);
  }
  {  // rouge clignotant 10 s = 10 clignotements exactement, puis éteint
    LedLogic l;
    l.on_answer(3, Pattern::RedBlink, 10000, 0);
    int rising = 0;
    bool prev = false;
    for (uint32_t t = 0; t < 10000; t += 10) {
      if (t % 1000 == 0 && t) l.on_answer(3, Pattern::RedBlink, 10000 - t, t);
      const bool on = at(l, t).red;
      if (on && !prev) ++rising;
      prev = on;
      CHECK(!at(l, t).green);
    }
    CHECK(rising == 10);
    l.on_answer(3, Pattern::RedBlink, 0, 10000);
    CHECK(!at(l, 10000).red && !at(l, 10500).red);
  }
  {  // rouge fixe, puis le serveur dit « éteint » => éteint immédiatement
    LedLogic l;
    l.on_answer(4, Pattern::RedSolid, 30000, 0);
    CHECK(at(l, 500).red);
    l.on_answer(5, Pattern::Off, 0, 1000);
    CHECK(!at(l, 1000).red && !at(l, 1001).green);
  }
  {  // changement de motif : la phase repart de zéro (allumé immédiatement)
    LedLogic l;
    l.on_answer(6, Pattern::GreenBlink, 100000, 0);
    l.on_answer(7, Pattern::RedBlink, 10000, 700);
    CHECK(at(l, 700).red && !at(l, 700).green);
  }
  {  // débordement du compteur millis() (environ 49 jours) : pas d'allumage parasite
    LedLogic l;
    const uint32_t t0 = 0xFFFFFF00u;
    l.on_answer(8, Pattern::GreenSolid, 1000, t0);
    CHECK(at(l, t0 + 500).green);
    CHECK(!at(l, t0 + 1000).green);
  }
  CHECK(parse_pattern("green_blink") == Pattern::GreenBlink);
  CHECK(parse_pattern("inconnu") == Pattern::Off);
  CHECK(parse_pattern(nullptr) == Pattern::Off);

  if (failures) {
    std::printf("%d echec(s)\n", failures);
    return 1;
  }
  std::printf("firmware : logique du voyant OK (toutes les verifications)\n");
  return 0;
}
