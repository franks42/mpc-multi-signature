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
      :working-dir         <abs path>}

   `opts` (all optional):
     :roles       — vector of role keywords; defaults to [:holder :figure :ic]
     :working-dir — absolute path to project root; auto-detected by default
     :bb-task     — bb task name used for every role; defaults to \"party\""
  ([] (start-orchestrator {}))
  ([{:keys [roles working-dir bb-task]
     :or   {roles   default-roles
            bb-task "party"}}]
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
                 [role (party/start! {:role role :working-dir wd :bb-task bb-task})]))]
     (log/log! {:level :info
                :id    :mpc-multi-signature.orchestrator.core/started
                :msg   "Orchestrator started"
                :data  {:roles (vec roles) :bb-task bb-task
                        :participant-ids participant-ids
                        :working-dir wd}})
     {:connections-by-role connections-by-role
      :participant-ids     participant-ids
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
