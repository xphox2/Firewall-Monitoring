package handlers

import (
	"net/http"
	"strconv"
	"testing"
	"time"

	"firewall-mon/internal/database"
	"firewall-mon/internal/models"

	"github.com/gin-gonic/gin"
)

func ircUpdateFixture(t *testing.T) (database.Store, *Handler) {
	t.Helper()
	db := database.NewDatabaseForTesting(t)
	if err := db.Gorm().AutoMigrate(&models.IRCServer{}, &models.IRCChannel{}, &models.IRCCommand{}); err != nil {
		t.Fatalf("migrate irc tables: %v", err)
	}
	return db, &Handler{db: db}
}

// ircPut builds a PUT context for an IRC update handler; code() reads the
// response status after the handler runs.
func ircPut(path string, id uint, body string) (*gin.Context, func() int) {
	c, rec := jsonReq(http.MethodPut, path, body)
	c.Params = gin.Params{{Key: "id", Value: strconv.FormatUint(uint64(id), 10)}}
	return c, func() int { return rec.Code }
}

// TestUpdateIRCServer_AllowList pins M-12: server-owned fields sent on an
// update (the UIs send the whole row back) are dropped, while editable fields
// still apply.
func TestUpdateIRCServer_AllowList(t *testing.T) {
	db, h := ircUpdateFixture(t)
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	srv := models.IRCServer{Name: "srv", ServerHost: "198.51.100.1", Nick: "bot",
		Status: "disconnected", CreatedAt: created}
	if err := db.Gorm().Create(&srv).Error; err != nil {
		t.Fatalf("seed server: %v", err)
	}

	c, code := ircPut("/admin/api/irc/servers/x", srv.ID,
		`{"name":"renamed","enabled":false,"status":"connected","last_error":"injected",`+
			`"last_connected":"2020-01-01T00:00:00Z","created_at":"2020-01-01T00:00:00Z",`+
			`"id":999,"channels":[{"channel_name":"#evil"}],"not_a_column":"x"}`)
	h.UpdateIRCServer(c)
	if code() != http.StatusOK {
		t.Fatalf("status = %d", code())
	}

	var got models.IRCServer
	if err := db.Gorm().First(&got, srv.ID).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.Name != "renamed" {
		t.Errorf("name = %q, want renamed (allowed field not applied)", got.Name)
	}
	if got.Status != "disconnected" {
		t.Errorf("status = %q, client-supplied status was honored", got.Status)
	}
	if got.LastError != "" {
		t.Errorf("last_error = %q, client-supplied value was honored", got.LastError)
	}
	if got.LastConnected != nil {
		t.Errorf("last_connected = %v, client-supplied value was honored", got.LastConnected)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("created_at = %v, want %v", got.CreatedAt, created)
	}
	var n int64
	db.Gorm().Model(&models.IRCChannel{}).Count(&n)
	if n != 0 {
		t.Errorf("channels association was written through an update (%d rows)", n)
	}
}

func TestUpdateIRCServer_RejectsBadPort(t *testing.T) {
	db, h := ircUpdateFixture(t)
	srv := models.IRCServer{Name: "srv", ServerHost: "198.51.100.1", Nick: "bot", ServerPort: 6697}
	db.Gorm().Create(&srv)

	for _, body := range []string{`{"server_port":0}`, `{"server_port":70000}`, `{"server_port":"6667"}`, `{"server_port":66.5}`,
		`{"reconnect_delay":-1}`, `{"id":5,"status":"connected"}`} {
		c, code := ircPut("/admin/api/irc/servers/x", srv.ID, body)
		h.UpdateIRCServer(c)
		if code() != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, code())
		}
	}
	// null (an emptied number input) means "unchanged".
	c, code := ircPut("/admin/api/irc/servers/x", srv.ID, `{"server_port":null,"name":"srv2"}`)
	h.UpdateIRCServer(c)
	if code() != http.StatusOK {
		t.Fatalf("null port: status = %d, want 200", code())
	}
	var got models.IRCServer
	db.Gorm().First(&got, srv.ID)
	if got.ServerPort != 6697 {
		t.Errorf("server_port = %d, want unchanged 6697", got.ServerPort)
	}
}

func TestUpdateIRCChannel_AllowList(t *testing.T) {
	db, h := ircUpdateFixture(t)
	srv := models.IRCServer{Name: "srv", ServerHost: "198.51.100.1", Nick: "bot"}
	db.Gorm().Create(&srv)
	ch := models.IRCChannel{ServerID: srv.ID, ChannelName: "#ops", Status: "pending"}
	if err := db.Gorm().Create(&ch).Error; err != nil {
		t.Fatalf("seed channel: %v", err)
	}

	c, code := ircPut("/admin/api/irc/channels/x", ch.ID,
		`{"channel_name":"#noc","admin_nicks":"alice","status":"joined",`+
			`"joined_at":"2020-01-01T00:00:00Z","updated_at":"2020-01-01T00:00:00Z","server":{"name":"x"}}`)
	h.UpdateIRCChannel(c)
	if code() != http.StatusOK {
		t.Fatalf("status = %d", code())
	}
	var got models.IRCChannel
	db.Gorm().First(&got, ch.ID)
	if got.ChannelName != "#noc" || got.AdminNicks != "alice" {
		t.Errorf("allowed fields not applied: name=%q admin_nicks=%q", got.ChannelName, got.AdminNicks)
	}
	if got.Status != "pending" {
		t.Errorf("status = %q, client-supplied status was honored", got.Status)
	}
	if got.JoinedAt != nil {
		t.Errorf("joined_at = %v, client-supplied value was honored", got.JoinedAt)
	}
}

func TestUpdateIRCChannel_ServerIDMustExist(t *testing.T) {
	db, h := ircUpdateFixture(t)
	srv := models.IRCServer{Name: "srv", ServerHost: "198.51.100.1", Nick: "bot"}
	db.Gorm().Create(&srv)
	other := models.IRCServer{Name: "other", ServerHost: "198.51.100.2", Nick: "bot"}
	db.Gorm().Create(&other)
	ch := models.IRCChannel{ServerID: srv.ID, ChannelName: "#ops"}
	db.Gorm().Create(&ch)

	for _, body := range []string{`{"server_id":4242}`, `{"server_id":0}`, `{"server_id":"1"}`, `{"server_id":1.5}`,
		`{"status_interval":-60}`, `{"id":5,"joined_at":"2020-01-01T00:00:00Z"}`} {
		c, code := ircPut("/admin/api/irc/channels/x", ch.ID, body)
		h.UpdateIRCChannel(c)
		if code() != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", body, code())
		}
	}
	var got models.IRCChannel
	db.Gorm().First(&got, ch.ID)
	if got.ServerID != srv.ID {
		t.Fatalf("server_id = %d after rejected moves, want %d", got.ServerID, srv.ID)
	}

	c, code := ircPut("/admin/api/irc/channels/x", ch.ID, `{"server_id":null,"channel_name":"#ops2"}`)
	h.UpdateIRCChannel(c)
	if code() != http.StatusOK {
		t.Fatalf("null server_id: status = %d, want 200 (unchanged)", code())
	}

	c, code = ircPut("/admin/api/irc/channels/x", ch.ID, `{"server_id":`+strconv.Itoa(int(other.ID))+`}`)
	h.UpdateIRCChannel(c)
	if code() != http.StatusOK {
		t.Fatalf("move to existing server: status = %d", code())
	}
	db.Gorm().First(&got, ch.ID)
	if got.ServerID != other.ID {
		t.Errorf("server_id = %d, want %d", got.ServerID, other.ID)
	}
}

func TestUpdateIRCCommand_AllowList(t *testing.T) {
	db, h := ircUpdateFixture(t)
	created := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	cmd := models.IRCCommand{Command: "!status", CommandType: "static", CreatedAt: created}
	if err := db.Gorm().Create(&cmd).Error; err != nil {
		t.Fatalf("seed command: %v", err)
	}

	c, code := ircPut("/admin/api/irc/commands/x", cmd.ID,
		`{"response":"ok","command":"","created_at":"2020-01-01T00:00:00Z","id":999}`)
	h.UpdateIRCCommand(c)
	if code() != http.StatusOK {
		t.Fatalf("status = %d", code())
	}
	var got models.IRCCommand
	db.Gorm().First(&got, cmd.ID)
	if got.Response != "ok" {
		t.Errorf("response = %q, allowed field not applied", got.Response)
	}
	if got.Command != "!status" {
		t.Errorf("command = %q, an empty trigger must leave it unchanged", got.Command)
	}
	if !got.CreatedAt.Equal(created) {
		t.Errorf("created_at = %v, want %v", got.CreatedAt, created)
	}

	c, code = ircPut("/admin/api/irc/commands/x", cmd.ID, `{"id":5,"updated_at":"2020-01-01T00:00:00Z"}`)
	h.UpdateIRCCommand(c)
	if code() != http.StatusBadRequest {
		t.Errorf("only server-owned fields: status = %d, want 400", code())
	}
}
