package site

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"kitty/constants"
	"kitty/database"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"gorm.io/datatypes"
)

const webAuthnSessionCookieName = "webauthn_session"
const webAuthnSessionTTL = 5 * time.Minute

var (
	webAuthnOnce     sync.Once
	webAuthnInstance *webauthn.WebAuthn
	webAuthnInitErr  error
)

// getWebAuthn lazily builds the WebAuthn relying-party configuration. RPID and
// origins are derived from the public URL in production, or localhost when
// running in debug mode.
func getWebAuthn() (*webauthn.WebAuthn, error) {
	webAuthnOnce.Do(func() {
		var rpID string
		var origins []string

		if constants.DEBUG_MODE {
			rpID = "localhost"
			origins = []string{
				"http://localhost:6835",
				"http://127.0.0.1:6835",
			}
		} else {
			parsed, err := url.Parse(constants.PUBLIC_URL)
			if err != nil || parsed.Hostname() == "" {
				webAuthnInitErr = errors.New("invalid PUBLIC_URL for WebAuthn configuration")
				return
			}
			rpID = parsed.Hostname()
			origins = []string{strings.TrimRight(constants.PUBLIC_URL, "/")}
		}

		webAuthnInstance, webAuthnInitErr = webauthn.New(&webauthn.Config{
			RPID:          rpID,
			RPDisplayName: constants.APP_NAME,
			RPOrigins:     origins,
		})
	})
	return webAuthnInstance, webAuthnInitErr
}

// webAuthnUser adapts an AdminUser (plus its loaded credentials) to the
// webauthn.User interface.
type webAuthnUser struct {
	user  *database.AdminUser
	creds []webauthn.Credential
}

func (u *webAuthnUser) WebAuthnID() []byte                         { return u.user.WebAuthnHandle }
func (u *webAuthnUser) WebAuthnName() string                       { return u.user.Username }
func (u *webAuthnUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u *webAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

// loadWebAuthnUser builds a webAuthnUser from an AdminUser, decoding all stored
// passkeys into webauthn.Credential values.
func loadWebAuthnUser(user *database.AdminUser) (*webAuthnUser, []database.Passkey, error) {
	var passkeys []database.Passkey
	if err := database.GetDB().Where("admin_user_id = ?", user.ID).Find(&passkeys).Error; err != nil {
		return nil, nil, err
	}

	creds := make([]webauthn.Credential, 0, len(passkeys))
	for _, pk := range passkeys {
		var c webauthn.Credential
		if err := json.Unmarshal(pk.Data, &c); err != nil {
			return nil, nil, err
		}
		creds = append(creds, c)
	}

	return &webAuthnUser{user: user, creds: creds}, passkeys, nil
}

// --- in-memory session-data store -------------------------------------------

type webAuthnSession struct {
	data    webauthn.SessionData
	expires time.Time
}

var (
	webAuthnSessions   = map[string]webAuthnSession{}
	webAuthnSessionsMu sync.Mutex
)

func storeWebAuthnSession(w http.ResponseWriter, data *webauthn.SessionData) error {
	idBytes := make([]byte, 32)
	if _, err := rand.Read(idBytes); err != nil {
		return err
	}
	id := base64.RawURLEncoding.EncodeToString(idBytes)

	webAuthnSessionsMu.Lock()
	// opportunistically evict expired entries
	now := time.Now()
	for k, v := range webAuthnSessions {
		if now.After(v.expires) {
			delete(webAuthnSessions, k)
		}
	}
	webAuthnSessions[id] = webAuthnSession{data: *data, expires: now.Add(webAuthnSessionTTL)}
	webAuthnSessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     webAuthnSessionCookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(webAuthnSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   !constants.DEBUG_MODE,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func popWebAuthnSession(w http.ResponseWriter, r *http.Request) (*webauthn.SessionData, error) {
	cookie, err := r.Cookie(webAuthnSessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil, errors.New("missing webauthn session")
	}

	webAuthnSessionsMu.Lock()
	sess, ok := webAuthnSessions[cookie.Value]
	delete(webAuthnSessions, cookie.Value)
	webAuthnSessionsMu.Unlock()

	// clear the cookie regardless of outcome
	http.SetCookie(w, &http.Cookie{
		Name:     webAuthnSessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !constants.DEBUG_MODE,
		SameSite: http.SameSiteLaxMode,
	})

	if !ok || time.Now().After(sess.expires) {
		return nil, errors.New("webauthn session expired")
	}
	return &sess.data, nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// --- registration (authenticated) -------------------------------------------

func PasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	wa, err := getWebAuthn()
	if err != nil {
		http.Error(w, "Passkeys are not configured", http.StatusInternalServerError)
		return
	}

	user := getSignedInUserOrFail(r)

	// Ensure the user has a stable WebAuthn handle.
	if len(user.WebAuthnHandle) == 0 {
		handle := make([]byte, 64)
		if _, err := rand.Read(handle); err != nil {
			http.Error(w, "Error starting passkey registration", http.StatusInternalServerError)
			return
		}
		user.WebAuthnHandle = handle
		if err := database.GetDB().Save(user).Error; err != nil {
			http.Error(w, "Error starting passkey registration", http.StatusInternalServerError)
			return
		}
	}

	waUser, _, err := loadWebAuthnUser(user)
	if err != nil {
		http.Error(w, "Error starting passkey registration", http.StatusInternalServerError)
		return
	}

	// Exclude already-registered credentials to avoid duplicate registrations.
	exclusions := make([]protocol.CredentialDescriptor, 0, len(waUser.creds))
	for _, c := range waUser.creds {
		exclusions = append(exclusions, c.Descriptor())
	}

	creation, sessionData, err := wa.BeginRegistration(
		waUser,
		webauthn.WithExclusions(exclusions),
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		http.Error(w, "Error starting passkey registration", http.StatusInternalServerError)
		return
	}

	if err := storeWebAuthnSession(w, sessionData); err != nil {
		http.Error(w, "Error starting passkey registration", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, creation)
}

func PasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	wa, err := getWebAuthn()
	if err != nil {
		http.Error(w, "Passkeys are not configured", http.StatusInternalServerError)
		return
	}

	user := getSignedInUserOrFail(r)

	sessionData, err := popWebAuthnSession(w, r)
	if err != nil {
		http.Error(w, "Passkey registration session expired, please try again", http.StatusBadRequest)
		return
	}

	waUser, _, err := loadWebAuthnUser(user)
	if err != nil {
		http.Error(w, "Error completing passkey registration", http.StatusInternalServerError)
		return
	}

	credential, err := wa.FinishRegistration(waUser, *sessionData, r)
	if err != nil {
		http.Error(w, "Could not verify passkey: "+err.Error(), http.StatusBadRequest)
		return
	}

	credJSON, err := json.Marshal(credential)
	if err != nil {
		http.Error(w, "Error storing passkey", http.StatusInternalServerError)
		return
	}

	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey"
	}
	if len(name) > 60 {
		name = name[:60]
	}

	passkey := database.Passkey{
		AdminUserID:  user.ID,
		Name:         name,
		CredentialID: base64.RawURLEncoding.EncodeToString(credential.ID),
		Data:         datatypes.JSON(credJSON),
	}
	if err := database.GetDB().Create(&passkey).Error; err != nil {
		http.Error(w, "Error storing passkey", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":   passkey.ID,
		"name": passkey.Name,
	})
}

// --- login (unauthenticated, discoverable) ----------------------------------

func PasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	wa, err := getWebAuthn()
	if err != nil {
		http.Error(w, "Passkeys are not configured", http.StatusInternalServerError)
		return
	}

	assertion, sessionData, err := wa.BeginDiscoverableLogin()
	if err != nil {
		http.Error(w, "Error starting passkey sign-in", http.StatusInternalServerError)
		return
	}

	if err := storeWebAuthnSession(w, sessionData); err != nil {
		http.Error(w, "Error starting passkey sign-in", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, assertion)
}

func PasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	wa, err := getWebAuthn()
	if err != nil {
		http.Error(w, "Passkeys are not configured", http.StatusInternalServerError)
		return
	}

	sessionData, err := popWebAuthnSession(w, r)
	if err != nil {
		http.Error(w, "Passkey sign-in session expired, please try again", http.StatusBadRequest)
		return
	}

	var matchedUser *database.AdminUser
	var matchedPasskeys []database.Passkey

	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		var user database.AdminUser
		if err := database.GetDB().Where("web_authn_handle = ?", userHandle).First(&user).Error; err != nil {
			return nil, errors.New("unknown passkey user")
		}
		waUser, passkeys, err := loadWebAuthnUser(&user)
		if err != nil {
			return nil, err
		}
		matchedUser = &user
		matchedPasskeys = passkeys
		return waUser, nil
	}

	credential, err := wa.FinishDiscoverableLogin(handler, *sessionData, r)
	if err != nil || matchedUser == nil {
		http.Error(w, "Passkey sign-in failed", http.StatusUnauthorized)
		return
	}

	// Persist the (possibly updated) credential, e.g. sign-count, for clone
	// detection on subsequent logins.
	credIDStr := base64.RawURLEncoding.EncodeToString(credential.ID)
	for _, pk := range matchedPasskeys {
		if pk.CredentialID == credIDStr {
			if credJSON, mErr := json.Marshal(credential); mErr == nil {
				database.GetDB().Model(&database.Passkey{}).Where("id = ?", pk.ID).
					Update("data", datatypes.JSON(credJSON))
			}
			break
		}
	}

	// Issue a session exactly like password login does.
	token, err := generateAuthToken()
	if err != nil {
		http.Error(w, "Error signing in", http.StatusInternalServerError)
		return
	}
	matchedUser.SessionToken = token
	database.GetDB().Save(matchedUser)

	http.SetCookie(w, &http.Cookie{
		Name:     string(AuthenticatedUserTokenCookieName),
		Value:    token,
		Path:     "/",
		MaxAge:   365 * 24 * 60 * 60,
		HttpOnly: true,
		Secure:   !constants.DEBUG_MODE,
		SameSite: http.SameSiteLaxMode,
	})

	writeJSON(w, http.StatusOK, map[string]string{"redirect": "/dashboard"})
}

// --- management (authenticated) ---------------------------------------------

func PasskeyList(w http.ResponseWriter, r *http.Request) {
	user := getSignedInUserOrFail(r)

	var passkeys []database.Passkey
	database.GetDB().Where("admin_user_id = ?", user.ID).Order("created_at ASC").Find(&passkeys)

	type item struct {
		ID        uint   `json:"id"`
		Name      string `json:"name"`
		CreatedAt string `json:"createdAt"`
	}
	out := make([]item, 0, len(passkeys))
	for _, pk := range passkeys {
		out = append(out, item{ID: pk.ID, Name: pk.Name, CreatedAt: pk.CreatedAt.Format("2006-01-02")})
	}
	writeJSON(w, http.StatusOK, out)
}

func PasskeyDelete(w http.ResponseWriter, r *http.Request) {
	user := getSignedInUserOrFail(r)

	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid passkey id", http.StatusBadRequest)
		return
	}

	result := database.GetDB().Where("id = ? AND admin_user_id = ?", uint(id), user.ID).
		Delete(&database.Passkey{})
	if result.Error != nil {
		http.Error(w, "Error deleting passkey", http.StatusInternalServerError)
		return
	}

	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
