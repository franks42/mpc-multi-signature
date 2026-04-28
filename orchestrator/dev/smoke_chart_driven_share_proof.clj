(ns smoke-chart-driven-share-proof
  "Smoke runner: drive share-possession-proof via the executable chart
   in both plain and binding modes; cryptographically verify the
   resulting transcripts.

   Run from the orchestrator/ directory:
     clojure -M:dev -m smoke-chart-driven-share-proof"
  (:require [mpc-multi-signature.orchestrator.chart-driven :as cd]
            [mpc-multi-signature.orchestrator.core :as orch]))

(defn- hex->bytes [^String s]
  (let [n (count s)
        ba (byte-array (/ n 2))]
    (dotimes [i (/ n 2)]
      (aset-byte ba i
                 (unchecked-byte (Integer/parseInt (subs s (* 2 i) (* 2 (inc i))) 16))))
    ba))

(defn- bytes->hex [^bytes bs]
  (apply str (for [b bs] (format "%02x" (bit-and b 0xff)))))

(defn- bind-context [verifier-nonce id-pub]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")]
    (.update md ^bytes verifier-nonce)
    (.update md ^bytes id-pub)
    (.digest md)))

(defn -main [& _]
  (let [o (orch/start-orchestrator {})
        kg (orch/keygen o [:holder :figure :ic] {:threshold 2})
        _  (assert (:share-handle kg))
        share-handle (:share-handle kg)

        ;; ===== PLAIN MODE =====
        plain-ctx "deadbeef00000000000000000000000000000000000000000000000000000000"
        proof-plain (cd/run-share-possession-proof-via-chart
                     o [:holder :figure :ic]
                     {:share-handle          share-handle
                      :challenge-context-hex plain-ctx})
        _ (assert (:proofs proof-plain)
                  (str "chart-driven share-proof (plain) failed: " proof-plain))
        _ (assert (= 3 (count (:proofs proof-plain)))
                  "missing per-party proofs")
        verify-plain (orch/verify-all-share-proofs proof-plain kg)
        _ (assert (:all-valid? verify-plain)
                  (str "plain proofs failed verification: " verify-plain))
        _ (println "plain-mode share-proof verified:" (:all-valid? verify-plain))

        ;; ===== BINDING MODE =====
        verifier-nonce-hex "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        nonce        (hex->bytes verifier-nonce-hex)
        pubkeys      (:identity-pubkeys o)
        ctx-by-role  (into {}
                           (for [r [:holder :figure :ic]
                                 :let [pub (hex->bytes (get pubkeys r))]]
                             [r (bytes->hex (bind-context nonce pub))]))
        proof-bound  (cd/run-share-possession-proof-via-chart
                      o [:holder :figure :ic]
                      {:share-handle                  share-handle
                       :challenge-context-hex-by-role ctx-by-role
                       :binding-mode?                 true})
        _ (assert (:proofs proof-bound)
                  (str "chart-driven share-proof (binding) failed: " proof-bound))
        ;; Sanity-check: every per-party transcript should carry both
        ;; the identity-pubkey-hex and the identity-signature-hex
        ;; fields that binding-mode adds.
        _ (doseq [[r p] (:proofs proof-bound)]
            (assert (:identity-pubkey-hex p)
                    (str "binding result missing :identity-pubkey-hex for " r))
            (assert (:identity-signature-hex p)
                    (str "binding result missing :identity-signature-hex for " r)))
        verify-bound (orch/verify-all-binding-share-proofs o proof-bound kg)
        _ (assert (:all-valid? verify-bound)
                  (str "binding proofs failed verification: " verify-bound))
        _ (println "binding-mode share-proof verified:" (:all-valid? verify-bound))]
    (println)
    (println "smoke OK")
    (println "  plain-mode all-valid?  :" (:all-valid? verify-plain))
    (println "  binding-mode all-valid?:" (:all-valid? verify-bound))
    (println "  → executable share-possession-proof chart drives both")
    (println "    modes correctly. Plain transcripts verify against")
    (println "    keygen verification shares; binding-mode transcripts")
    (println "    additionally verify the Ed25519 identity signature")
    (println "    over the proof bytes.")
    (orch/stop-orchestrator o)
    (System/exit 0)))
