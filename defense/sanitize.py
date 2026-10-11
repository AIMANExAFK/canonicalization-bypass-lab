#!/usr/bin/env python3
"""Assainisseur défensif contre l'attaque « vs16 » sur le watermarking de texte.

Principe (cf. README) : la normalisation Unicode standard (NFC/NFKC) NE retire PAS
les sélecteurs de variation ni les caractères zéro-largeur. Un détecteur robuste doit
donc, AVANT toute re-tokenisation :
  1. détecter une densité anormale de caractères invisibles (signe de trafic) ;
  2. les stripper pour que la tokenisation recolle à celle de génération.

Ce fichier est DÉFENSIF : il nettoie / flague un texte, il ne fabrique pas d'attaque.
"""

from __future__ import annotations
import unicodedata

# Plages de caractères "invisibles" exploitées pour désynchroniser la tokenisation.
VARIATION_SELECTORS = set(range(0xFE00, 0xFE10))          # VS1–VS16
VARIATION_SELECTORS |= set(range(0xE0100, 0xE01F0))        # VS supplémentaires
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF}      # ZWSP, ZWNJ, ZWJ, WJ, BOM

INVISIBLE = VARIATION_SELECTORS | ZERO_WIDTH

# Au-delà de ce ratio de caractères invisibles, on considère le texte comme trafiqué.
ANOMALY_RATIO = 0.05


def count_invisible(text: str) -> int:
    """Nombre de caractères invisibles suspects dans le texte."""
    return sum(ord(ch) in INVISIBLE for ch in text)


def is_tampered(text: str, ratio: float = ANOMALY_RATIO) -> bool:
    """True si la densité de caractères invisibles dépasse le seuil d'anomalie.

    Du texte humain n'en contient quasiment jamais : une densité élevée est
    elle-même la signature de l'attaque, triviale à flaguer.
    """
    if not text:
        return False
    return count_invisible(text) / len(text) > ratio


def sanitize(text: str) -> str:
    """Retire les caractères invisibles, puis applique une normalisation NFC.

    L'ordre est volontaire : on strippe AVANT de normaliser/re-tokeniser, sinon
    NFC laisse passer les sélecteurs et la faille reste ouverte.
    """
    stripped = "".join(ch for ch in text if ord(ch) not in INVISIBLE)
    return unicodedata.normalize("NFC", stripped)


def inspect(text: str) -> dict:
    """Rapport d'analyse prêt à logguer."""
    n_inv = count_invisible(text)
    return {
        "longueur": len(text),
        "invisibles": n_inv,
        "ratio": round(n_inv / len(text), 4) if text else 0.0,
        "trafique": is_tampered(text),
        "texte_propre": sanitize(text),
    }


if __name__ == "__main__":
    propre = "the cat sat on the mat"
    # Simulation d'un texte "attaqué" : U+FE0F (VS16, invisible) inséré entre des caractères.
    attaque = "t️h️e c️a️t s️a️t on the mat"

    for nom, txt in [("texte propre", propre), ("texte attaqué", attaque)]:
        r = inspect(txt)
        print(f"[{nom}]")
        print(f"  invisibles = {r['invisibles']}  ratio = {r['ratio']}  trafiqué = {r['trafique']}")
        print(f"  nettoyé    = {r['texte_propre']!r}")
        print()

    # La re-tokenisation doit se faire sur le texte NETTOYÉ.
    assert sanitize(attaque) == propre, "le nettoyage doit restaurer le texte d'origine"
    assert is_tampered(attaque) and not is_tampered(propre)
    print("OK — anomalie détectée et texte restauré avant re-tokenisation.")
