# Demonstration of the small state attack

The small state attack can recover the state of the Micali-Schnorr pseudorandom
generator when the state has size $r < n / e$.

The improved small state attack can recover the state when it has size $r \leq
(n - 1 + m \log_2 n) / e$ for some constant $m$.

The implementation demonstrates both attacks with $n = 2048$ and $e = 3$.
