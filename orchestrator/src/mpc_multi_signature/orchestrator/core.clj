(ns mpc-multi-signature.orchestrator.core
  "REPL-facing entry. Spawns party subprocesses, exposes ceremony
   functions (keygen, triple-generation, presign, sign, reshare), and
   shuts everything down cleanly.

   `sign-edn-message` is the high-level convenience: takes any EDN
   payload, canonicalizes via cedn, SHA-256s, drives the full
   triple→presign→sign chain, and cross-verifies the resulting
   signature with signet (BouncyCastle-backed, independent of the
   threshold-signatures crate's own verify path)."
  (:require [cedn.core :as cedn]
            [mpc-multi-signature.orchestrator.ceremony :as ceremony]
            [mpc-multi-signature.orchestrator.party-connection :as party]
            [mpc-multi-signature.orchestrator.telemetry :as telemetry]
            [taoensso.trove :as log])
  (:import (java.security MessageDigest)))

(def ^:private default-roles
  [:holder :figure :ic])

(defn- project-root
  "The working directory used when spawning party subprocesses. The
   orchestrator runs from `orchestrator/` (deps.edn lives there); the
   parties run from the project root, where bb.edn lives."
  []
  (-> (System/getProperty "user.dir")
      (java.io.File.)
      .getCanonicalFile
      .getParentFile
      .getCanonicalPath))

(defn start-orchestrator
  "Spawn one party subprocess per role and return an orchestrator
   handle:

     {:connections-by-role {:holder ..., :figure ..., :ic ...}
      :participant-ids     {role -> int}
      :identity-pubkeys    {role -> hex string}
      :working-dir         <abs path>}

   Stage 5b.2: each bb wrapper generates its own Ed25519 identity
   keypair at startup and announces its public key via a
   :party/identity handshake message. start-orchestrator blocks on
   each handshake before returning. The orchestrator never sees any
   party's private key — production placement of the identity key
   material.

   `opts` (all optional):
     :roles            — vector of role keywords; defaults to [:holder :figure :ic]
     :working-dir      — absolute path to project root; auto-detected by default
     :bb-task          — bb task name used for every role; defaults to \"party\"
     :handshake-timeout-ms — per-party handshake deadline; defaults to 5000"
  ([] (start-orchestrator {}))
  ([{:keys [roles working-dir bb-task handshake-timeout-ms]
     :or   {roles                default-roles
            bb-task              "party"
            handshake-timeout-ms 5000}}]
   (telemetry/ensure-initialized!)
   (let [wd (or working-dir (project-root))
         ;; Canonical role↔int map: each role's participant-id is its
         ;; index in the orchestrator's :roles vector. Stable across all
         ;; ceremonies — the threshold-signatures crate's shares are
         ;; bound to specific integer participant ids; if those drift
         ;; between ceremonies, presign rejects with "incorrect shares".
         participant-ids (into {} (map-indexed (fn [i r] [r i]) roles))
         connections-by-role
         (into {}
               (for [role roles]
                 [role (party/start! {:role role :working-dir wd :bb-task bb-task})]))
         ;; Block on the :party/identity handshake from each party
         ;; before declaring the orchestrator ready. Private key stays
         ;; with the bb wrapper; we capture only the announced pubkey.
         identity-pubkeys
         (into {}
               (for [role roles
                     :let [conn (get connections-by-role role)
                           hs   (party/recv-handshake! conn handshake-timeout-ms)]]
                 [role (:identity/pubkey-hex hs)]))]
     (log/log! {:level :info
                :id    :mpc-multi-signature.orchestrator.core/started
                :msg   "Orchestrator started"
                :data  {:roles (vec roles) :bb-task bb-task
                        :participant-ids participant-ids
                        :identity-pubkeys identity-pubkeys
                        :working-dir wd}})
     {:connections-by-role connections-by-role
      :participant-ids     participant-ids
      :identity-pubkeys    identity-pubkeys
      :working-dir         wd})))

(defn keygen
  ([orch participants] (keygen orch participants {}))
  ([orch participants opts] (ceremony/run-keygen orch participants opts)))

(defn triple-generation
  ([orch participants] (triple-generation orch participants {}))
  ([orch participants opts] (ceremony/run-triple-generation orch participants opts)))

(defn presign
  "Run a presign ceremony.
   `opts` requires :share-handle and :triple-handle from earlier ceremonies."
  [orch participants opts]
  (ceremony/run-presign orch participants opts))

(defn sign
  "Run a sign ceremony with a pre-computed digest.
   `opts` requires :coordinator (role keyword), :share-handle,
   :presig-handle, :digest-hex (32-byte hex string)."
  [orch participants opts]
  (ceremony/run-sign orch participants opts))

(defn reshare
  "Run a reshare ceremony.
   `opts` requires :old-participants, :new-participants,
   :old-share-handle, :public-key-hex (continuity anchor)."
  [orch opts]
  (ceremony/run-reshare orch opts))

(defn share-possession-proof
  "Run a share-possession proof ceremony. `opts` requires
   :share-handle and :challenge-context-hex."
  [orch participants opts]
  (ceremony/run-share-possession-proof orch participants opts))

(defn- bind-context
  "Compute the per-party bound challenge context for an identity-share
   binding proof: H(verifier-nonce || party-id-pubkey-bytes)."
  [^bytes verifier-nonce ^bytes id-pub-bytes]
  (let [md (java.security.MessageDigest/getInstance "SHA-256")]
    (.update md verifier-nonce)
    (.update md id-pub-bytes)
    (.digest md)))

;; ============================================================
;; High-level: canonicalize an EDN payload, sign, cross-verify
;; ============================================================

(defn- sha256
  "32-byte SHA-256 of a byte array."
  ^bytes [^bytes bs]
  (.digest (MessageDigest/getInstance "SHA-256") bs))

(defn- bytes->hex [^bytes bs]
  (apply str (map #(format "%02x" (bit-and % 0xff)) bs)))

(defn- hex->bytes [^String s]
  (let [n (quot (count s) 2)
        out (byte-array n)]
    (dotimes [i n]
      (aset out i (unchecked-byte (Integer/parseInt (subs s (* i 2) (+ (* i 2) 2)) 16))))
    out))

(defn canonical-digest
  "Take an arbitrary EDN value, canonicalize it via cedn, return
   {:canonical-bytes <bytes> :digest-hex <hex>}."
  [edn-value]
  (let [canonical (cedn/canonical-bytes edn-value)
        digest    (sha256 canonical)]
    {:canonical-bytes canonical
     :digest-hex      (bytes->hex digest)}))

(defn- jca-secp256k1-verify-digest
  "Direct JCA-via-BC verify of a 32-byte SHA-256 digest against a
   secp256k1 ECDSA signature. Bypasses signet's `verify` (which always
   SHA-256s the message internally) because in our pipeline the
   digest is pre-computed by the canonical-edn step.

   Returns true iff the signature is valid; never throws."
  [^bytes pub-bytes ^bytes digest-bytes ^bytes sig-bytes]
  (try
    (let [;; Reuse signet.impl.jvm-secp256k1's private helpers via
          ;; requiring-resolve — both for the X.509-wrap-and-decompress
          ;; pubkey path and the raw-or-DER auto-detect+coerce.
          compressed->jca-public @(requiring-resolve
                                   'signet.impl.jvm-secp256k1/compressed->jca-public)
          coerce-sig->der        @(requiring-resolve
                                   'signet.impl.jvm-secp256k1/coerce-sig->der)
          pub-key  (compressed->jca-public pub-bytes)
          der-sig  (coerce-sig->der sig-bytes)
          verifier (java.security.Signature/getInstance "NONEwithECDSA" "BC")]
      (.initVerify verifier pub-key)
      (.update verifier digest-bytes)
      (.verify verifier der-sig))
    (catch Exception _ false)))

(defn cross-verify-signature
  "Independently verify a threshold-signatures-produced ECDSA signature
   using signet's BouncyCastle-backed JCA path — zero shared crypto
   code with the threshold-signatures crate, so this is a real
   cross-validation.

   Returns boolean."
  [pubkey-hex digest-hex sig-hex]
  (let [pub-bytes    (hex->bytes pubkey-hex)
        sig-bytes    (hex->bytes sig-hex)
        digest-bytes (hex->bytes digest-hex)]
    (jca-secp256k1-verify-digest pub-bytes digest-bytes sig-bytes)))

;; ============================================================
;; Schnorr PoK verifier (Stage 5a — share-possession proof)
;; ============================================================
;;
;; Verifies a transcript produced by crypto-core's schnorr_pok_share.
;; Math: given X_i (verification share), R (compressed point), s
;; (scalar), and the verifier-supplied challenge_context, recompute
;; c = SHA-256(R || X_i || context) and check s·G == R + c·X_i.
;;
;; Implementation uses BC's secp256k1 curve parameters via reflection
;; (BC is on classpath via signet 0.5.0). Independent of both the
;; threshold-signatures crate and our crypto-core's Rust prover —
;; genuine cross-validation.

(defn- bc-secp256k1-params
  "Lazy-resolve BC's secp256k1 ECNamedCurveParameterSpec via reflection
   so we don't trigger BC class loading at namespace load time
   (which would break bb compatibility for unrelated paths)."
  []
  (let [cls (Class/forName "org.bouncycastle.jce.ECNamedCurveTable")
        m   (.getMethod cls "getParameterSpec" (into-array Class [String]))]
    (.invoke m nil (into-array Object ["secp256k1"]))))

(defn- decode-point [params ^bytes compressed]
  (.decodePoint (.getCurve params) compressed))

(defn- verify-share-pok
  "Returns true iff the Schnorr PoK transcript verifies against the
   given verification share and challenge context. Never throws on
   malformed inputs — returns false."
  [^bytes vshare-bytes ^bytes proof-bytes ^bytes challenge-context]
  (try
    (when-not (and (= 33 (count vshare-bytes))
                   (= 65 (count proof-bytes)))
      (throw (ex-info "bad input lengths" {})))
    (let [r-bytes (java.util.Arrays/copyOfRange proof-bytes 0 33)
          s-bytes (java.util.Arrays/copyOfRange proof-bytes 33 65)
          params  (bc-secp256k1-params)
          big-r   (decode-point params r-bytes)
          big-x   (decode-point params vshare-bytes)
          c-digest (let [md (java.security.MessageDigest/getInstance "SHA-256")]
                     (.update md r-bytes)
                     (.update md vshare-bytes)
                     (.update md challenge-context)
                     (.digest md))
          n        (.getN params)
          c        (-> (java.math.BigInteger. 1 c-digest) (.mod n))
          s        (-> (java.math.BigInteger. 1 s-bytes) (.mod n))
          g        (.getG params)
          ;; Check  s·G == R + c·X_i.
          s-g      (-> (.multiply g s) .normalize)
          c-x      (.multiply big-x c)
          rhs      (-> (.add big-r c-x) .normalize)]
      (and (= (.getAffineXCoord s-g) (.getAffineXCoord rhs))
           (= (.getAffineYCoord s-g) (.getAffineYCoord rhs))))
    (catch Exception _ false)))

(defn verify-share-possession-proof
  "Verify a single party's share-possession proof.
     vshare-hex          — 33-byte sec1 compressed verification share (hex)
     proof-hex           — 65-byte Schnorr transcript (R || s) (hex)
     challenge-context-hex — verifier-supplied bytes the proof was bound to"
  [vshare-hex proof-hex challenge-context-hex]
  (verify-share-pok (hex->bytes vshare-hex)
                    (hex->bytes proof-hex)
                    (hex->bytes challenge-context-hex)))

(defn verify-all-share-proofs
  "Given the result map from `share-possession-proof` and the
   per-party verification shares from a prior keygen, verify every
   party's PoK. Also checks that the verification share each party
   reported in their proof matches what keygen recorded — catches
   parties who tried to swap their X_i.

   Returns {:all-valid? bool :per-party {role bool}}"
  [proof-result keygen-result]
  (let [vshares (:verification-shares keygen-result)
        proofs  (:proofs proof-result)
        per     (into {}
                      (for [[r {:keys [verification-share-hex proof-hex challenge-context-hex]}] proofs]
                        [r (and (= verification-share-hex (get vshares r))
                                (verify-share-possession-proof
                                 verification-share-hex proof-hex challenge-context-hex))]))]
    {:all-valid? (every? true? (vals per))
     :per-party  per}))

;; ============================================================
;; Identity-share binding proof (Stage 5a; bb-wrapper-side as of 5b.2)
;; ============================================================
;;
;; Welds an Ed25519 identity key to its MPC share via two checks:
;;   1. Schnorr challenge bound to the identity public key (non-
;;      transferability — Alice can't replay Bob's PoK as her own).
;;   2. Ed25519 signature over the PoK transcript binds the identity
;;      holder to the proof.
;;
;; Stage 5b.2 placement: each party holds its own Ed25519 private key
;; at the bb wrapper. The orchestrator never sees private keys; it
;; passes :binding-mode? true into the share-possession-proof
;; ceremony, the bb wrapper signs the proof bytes locally after
;; crypto-core emits them, and the augmented transcript flows back
;; through the normal ceremony-complete path.

(defn binding-share-possession-proof
  "Run a share-possession proof bound to each party's Ed25519 identity
   key. The orchestrator computes per-party bound challenge contexts
   ctx_r = SHA-256(verifier-nonce || K_id_pub_r) using the pubkeys
   each bb wrapper announced at startup; the binding signature itself
   is produced by each bb wrapper during the ceremony.

   Returns:
     {:proofs {role {:verification-share-hex ...
                     :proof-hex ...
                     :challenge-context-hex ... (the bound context)
                     :identity-pubkey-hex ...
                     :identity-signature-hex ...}}
      :verifier-nonce-hex <hex>
      :ceremony/id <uuid>}"
  [{:keys [identity-pubkeys] :as orch} participants
   {:keys [share-handle verifier-nonce-hex deadline-ms]
    :or   {deadline-ms 30000}}]
  (assert share-handle       "binding-share-possession-proof: :share-handle required")
  (assert verifier-nonce-hex "binding-share-possession-proof: :verifier-nonce-hex required")
  (let [nonce        (hex->bytes verifier-nonce-hex)
        ctx-by-role  (into {}
                           (for [r participants
                                 :let [pub-hex (or (get identity-pubkeys r)
                                                   (throw (ex-info (str "no identity pubkey for role " r)
                                                                   {:role r})))
                                       pub     (hex->bytes pub-hex)]]
                             [r (bytes->hex (bind-context nonce pub))]))
        proof-result (ceremony/run-share-possession-proof
                      orch participants
                      {:share-handle                  share-handle
                       :challenge-context-hex-by-role ctx-by-role
                       :binding-mode?                 true
                       :deadline-ms                   deadline-ms})]
    (when (:error proof-result)
      (throw (ex-info "share-possession-proof failed" proof-result)))
    {:proofs             (:proofs proof-result)
     :verifier-nonce-hex verifier-nonce-hex
     :ceremony/id        (:ceremony/id proof-result)}))

(defn verify-binding-share-proof
  "Verify a single party's identity-share binding proof:
     1. Claimed identity pubkey matches the registered one.
     2. Ed25519 signature over the proof transcript verifies against
        the registered identity public key.
     3. Schnorr PoK with the challenge context bound to that identity
        public key.
   Returns boolean."
  [registered-id-pubkey-hex
   {:keys [verification-share-hex proof-hex challenge-context-hex
           identity-pubkey-hex identity-signature-hex]}]
  (and (= registered-id-pubkey-hex identity-pubkey-hex)
       (let [signet-verify  (requiring-resolve 'signet.sign/verify)
             signet-pub-rec (requiring-resolve 'signet.key/->Ed25519PublicKey)
             pub            (signet-pub-rec :signet/ed25519-public-key
                                            :Ed25519
                                            (hex->bytes registered-id-pubkey-hex))
             msg            (hex->bytes proof-hex)
             sig            (hex->bytes identity-signature-hex)]
         (signet-verify pub msg sig))
       (verify-share-possession-proof
        verification-share-hex proof-hex challenge-context-hex)))

(defn verify-all-binding-share-proofs
  "Verify every party's identity-share binding proof against the
   orchestrator's registered identity public keys (announced by each
   bb wrapper at startup) + the verification shares from a prior
   keygen.
   Returns {:all-valid? bool :per-party {role bool}}"
  [orch proof-result keygen-result]
  (let [vshares  (:verification-shares keygen-result)
        pubkeys  (:identity-pubkeys orch)
        per      (into {}
                       (for [[r party-proof] (:proofs proof-result)
                             :let [registered-id-hex (get pubkeys r)
                                   vshare-match?     (= (:verification-share-hex party-proof)
                                                        (get vshares r))]]
                         [r (and registered-id-hex
                                 vshare-match?
                                 (verify-binding-share-proof registered-id-hex party-proof))]))]
    {:all-valid? (every? true? (vals per))
     :per-party  per}))

(defn sign-edn-message
  "High-level sign: take an EDN payload, canonicalize, hash, drive the
   triple-generation → presign → sign chain, cross-verify with signet,
   return the result.

   `opts` requires:
     :coordinator   — role keyword (defaults to :figure for routine signing)
     :public-key-hex — for cross-verification
     :share-handle  — from a prior keygen result

   Returns:
     {:signature-hex <hex 64-byte raw r||s>
      :digest-hex    <hex>
      :public-key-hex <hex>
      :cross-verified? bool
      :coordinator   <role>
      :ceremony-ids  {:triples ... :presign ... :sign ...}}"
  [orch participants edn-payload
   {:keys [coordinator public-key-hex share-handle deadline-ms]
    :or   {coordinator :figure deadline-ms 60000}
    :as   _opts}]
  (assert public-key-hex "sign-edn-message: :public-key-hex required")
  (assert share-handle   "sign-edn-message: :share-handle required")
  (let [{:keys [digest-hex]} (canonical-digest edn-payload)
        triples-result       (triple-generation orch participants
                                                {:threshold 2 :deadline-ms deadline-ms})
        _ (when (:error triples-result)
            (throw (ex-info "triple-generation failed" triples-result)))
        triple-handle        (:triple-handle triples-result)
        presign-result       (presign orch participants
                                      {:threshold 2
                                       :share-handle share-handle
                                       :triple-handle triple-handle
                                       :deadline-ms deadline-ms})
        _ (when (:error presign-result)
            (throw (ex-info "presign failed" presign-result)))
        presig-handle        (:presig-handle presign-result)
        sign-result          (sign orch participants
                                   {:threshold 2
                                    :coordinator coordinator
                                    :share-handle share-handle
                                    :presig-handle presig-handle
                                    :digest-hex digest-hex
                                    :deadline-ms deadline-ms})
        _ (when (:error sign-result)
            (throw (ex-info "sign failed" sign-result)))
        sig-hex              (:signature-hex sign-result)
        cross?               (cross-verify-signature public-key-hex digest-hex sig-hex)]
    {:signature-hex   sig-hex
     :digest-hex      digest-hex
     :public-key-hex  public-key-hex
     :cross-verified? cross?
     :coordinator     coordinator
     :ceremony-ids    {:triples (:ceremony/id triples-result)
                       :presign (:ceremony/id presign-result)
                       :sign    (:ceremony/id sign-result)}}))

(defn stop-orchestrator
  "Stop all party subprocesses. Returns a map of role -> exit code."
  [{:keys [connections-by-role]}]
  (let [exits (into {}
                    (for [[role conn] connections-by-role]
                      [role (party/stop! conn)]))]
    (log/log! {:level :info
               :id    :mpc-multi-signature.orchestrator.core/stopped
               :msg   "Orchestrator stopped"
               :data  {:exits exits}})
    exits))
