#!/usr/bin/env python3
from core.vt import VTHunter

vt = VTHunter()

# vt.pull_vt_feed()
# vt.vt_mass_query(5850533070503936, "19a6e53ab4f20f52e52b25b3d4f1d8e10355e1e4dc672f23b4215462525c7adc")
vt.run_analysis('19a6e53ab4f20f52e52b25b3d4f1d8e10355e1e4dc672f23b4215462525c7adc')
