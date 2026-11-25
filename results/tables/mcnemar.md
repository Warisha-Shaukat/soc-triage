| split | model | first | second | n pairs | only first correct | only second correct | accuracy difference (second - first) | exact p |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev | qwen3:8b-q4_K_M | A1 rules | B LLM, no guard | 209 | 0 | 15 | +7.2 points | 6.104e-05 |
| dev | qwen3:8b-q4_K_M | A2 rules | B LLM, no guard | 209 | 36 | 33 | -1.4 points | 0.8099 |
| dev | qwen3:8b-q4_K_M | A1 rules | B LLM + guard | 209 | 8 | 24 | +7.7 points | 0.007 |
| dev | qwen3:8b-q4_K_M | A2 rules | B LLM + guard | 209 | 28 | 26 | -1.0 points | 0.8919 |
| dev | qwen3:8b-q4_K_M | B LLM, no guard | B LLM + guard | 209 | 9 | 10 | +0.5 points | 1 |
