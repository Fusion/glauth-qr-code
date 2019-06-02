package main

// ░░░▀█▀░█▄█░█▀█░█▀█░█▀▄░▀█▀░█▀▀░░
// ░░░░█░░█░█░█▀▀░█░█░█▀▄░░█░░▀▀█░░
// ░░░▀▀▀░▀░▀░▀░░░▀▀▀░▀░▀░░▀░░▀▀▀░░

import (
  "os"
  "os/user"
  "github.com/op/go-logging"
  "database/sql"
  _ "github.com/mattn/go-sqlite3"
  "html/template"
  "net/http"
  "fmt"
  "regexp"
  "math/rand"
  "time"
  "encoding/base32"
  "encoding/base64"
  "crypto/sha256"
  "github.com/BurntSushi/toml"
  "github.com/urfave/cli"
  qrcode "github.com/skip2/go-qrcode"
  uuid   "github.com/satori/go.uuid"
  "gopkg.in/src-d/go-git.v4"
  "gopkg.in/src-d/go-git.v4/storage/filesystem"
  "gopkg.in/src-d/go-billy.v4/osfs"
  "gopkg.in/src-d/go-git.v4/plumbing/cache"
  "gopkg.in/src-d/go-git.v4/plumbing/object"
)


func main() {

  const HOME_URL = "http://192.168.1.89:8080"
  const ISSUER_NAME = "VwbLabs"
  const CONFIG_PATH = "../config"
  const CONFIG_FILE = "cfr.cfg"
  const CONFIG_FILE_PATH = CONFIG_PATH + "/" + CONFIG_FILE
  const APP_NAME = "totpqrapp"

  correct_account_pattern, _ := regexp.Compile("[^a-zA-Z0-9-_]+")
  log := logging.MustGetLogger(APP_NAME)

// ░░░█░█░█▀▀░█░░░█▀█░█▀▀░█▀▄░█▀▀░░
// ░░░█▀█░█▀▀░█░░░█▀▀░█▀▀░█▀▄░▀▀█░░
// ░░░▀░▀░▀▀▀░▀▀▀░▀░░░▀▀▀░▀░▀░▀▀▀░░

  init := func() {
    logging.SetBackend(logging.NewLogBackend(os.Stderr, "", 0))
    logging.SetLevel(logging.DEBUG, APP_NAME)
    logging.SetFormatter(logging.MustStringFormatter(
       `%{color}%{time:15:04:05.000} %{shortfunc} > %{level:.4s} %{id:03x}%{color:reset} %{message}`,))
  }


  infoToLink := func(qrType string, qrIssuer string, qrAccount string, qrSecret string) string {
    link := fmt.Sprintf(
      "otpauth://%s/%s:%s?secret=%s&issuer=%s",
      qrType,
      qrIssuer, qrAccount,
      qrSecret,
      qrIssuer,
    )
    log.Debug(fmt.Sprintf("Generated link: %s", link))
    return link
  }


  randomString := func(size int) string {
    rand.Seed(time.Now().UnixNano())
    var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
    r := make([]rune, size)
    for i := range r {
        r[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(r)
  }

// ░░░█▀▀░█▀█░█▀█░█▀▀░▀█▀░█▀▀░░
// ░░░█░░░█░█░█░█░█▀▀░░█░░█░█░░
// ░░░▀▀▀░▀▀▀░▀░▀░▀░░░▀▀▀░▀▀▀░░

  type configLdapData struct {
    Enabled bool
    Listen string
  }
  type configLdapsData struct {
    Enabled bool
    Listen string
    Cert string
    Key string
  }
  type configBackendData struct {
    Datastore string
    Basedn string
  }
  type configUsersData struct {
    Name string
    Unixid int
    Primarygroup int
    Passsha256 string
    Otpsecret string
  }
  type configGroupsData struct {
    Name string
    Unixid int
  }
  type configApiData struct {
    Enabled bool
    Tls bool
    Listen string
    Cert string
    Key string
  }
  type configData struct {
    Debug bool
    Syslog bool
    Ldap configLdapData
    Ldaps configLdapsData
    Backend configBackendData
    Users []configUsersData
    Groups []configGroupsData
    Api configApiData
  }

  readConfig := func() (*configData, bool) {
    var config configData
    _, err := toml.DecodeFile(CONFIG_FILE_PATH, &config)
    if err != nil {
      log.Error("Error decoding config")
      fmt.Printf(err.Error())
      return nil, false
    }
    return &config, true
  }


  writeConfig := func(config *configData) {
    r, err := git.PlainOpen(CONFIG_PATH)
    if err != nil {
      fs := osfs.New(CONFIG_PATH)
      dot, _ := fs.Chroot(".git")
      storage := filesystem.NewStorage(dot, cache.NewObjectLRUDefault())
      git.Init(storage, fs)

      r, err = git.PlainOpen(CONFIG_PATH)
      if err != nil {
        log.Error("Error opening config directory.")
        fmt.Printf(err.Error())
        return
      }

      w, _ := r.Worktree()
      w.Add(CONFIG_FILE)
      w.Commit("Initial Commit -- Automated",  &git.CommitOptions{
        Author: &object.Signature{
          Name:  "totpqrapp",
          Email: "support@voilaweb.com",
          When:  time.Now(),
        },
      })
    }

    file, err := os.Create(CONFIG_FILE_PATH)
    if err != nil {
      log.Error("Error writing config")
      fmt.Printf(err.Error())
      return
    }
    defer file.Close()
    toml.NewEncoder(file).Encode(config)

    user, err := user.Current()

    w, _ := r.Worktree()
    w.Add(CONFIG_FILE)
    w.Commit("Iterative Save -- Automated",  &git.CommitOptions{
      Author: &object.Signature{
        Name:  fmt.Sprintf("%s (%s)", user.Username, user.Uid),
        Email: "support@voilaweb.com",
        When:  time.Now(),
      },
    })
  }


  test := func(w http.ResponseWriter, r *http.Request) {
    readConfig()
  }


// ░░░▀█▀░█▀█░█░█░▀█▀░▀█▀░█▀▀░░
// ░░░░█░░█░█░▀▄▀░░█░░░█░░█▀▀░░
// ░░░▀▀▀░▀░▀░░▀░░▀▀▀░░▀░░▀▀▀░░

  type InvitePageData struct {
    Account string
    Link    string
  }

  invite := func(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles("assets/invite.html"))

    values := r.URL.Query()
    raw_account, ok := values["account"]
    if !ok {
      http.Error(w,  "You forgot to define 'account'", http.StatusInternalServerError)
      return
    }
    account := correct_account_pattern.ReplaceAllString(raw_account[0], "")

    db, err := sql.Open("sqlite3", "./data/invites.db")
    if err != nil {
      log.Error("Error opening database")
      http.Error(w,  "Error opening database", http.StatusInternalServerError)
      return
    }
    defer db.Close()

    // Create db if necessary
    statement, _ := db.Prepare("CREATE TABLE IF NOT EXISTS invitees (id INTEGER PRIMARY KEY, account TEXT, token TEXT, created DATETIME DEFAULT CURRENT_TIMESTAMP, used BOOLEAN DEFAULT 0)")
    statement.Exec()
    statement, _ = db.Prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_account on invitees(account)")
    statement.Exec()

    // Purge old invites
    statement, _ = db.Prepare("DELETE FROM invitees WHERE (created <= datetime('now', '-10 days'))")
    statement.Exec()

    // Proper invite insert
    token, _ := uuid.NewV4()
    statement, _ = db.Prepare("INSERT OR REPLACE INTO invitees (account, token) VALUES (?, ?)")
    statement.Exec(account, token)

    log.Notice(fmt.Sprintf("Generated invitee key for account %s", account))

    data := InvitePageData{
              Account: account,
              Link: fmt.Sprintf("%s/onboard?token=%s", HOME_URL, token),
            }
    tmpl.Execute(w, data)
  }


// ░░░█░░░█▀█░█▀█░█▀▄░▀█▀░█▀█░█▀▀░░░█▀█░█▀█░█▀▀░█▀▀░░
// ░░░█░░░█▀█░█░█░█░█░░█░░█░█░█░█░░░█▀▀░█▀█░█░█░█▀▀░░
// ░░░▀▀▀░▀░▀░▀░▀░▀▀░░▀▀▀░▀░▀░▀▀▀░░░▀░░░▀░▀░▀▀▀░▀▀▀░░

  type PrePageData struct {
    Link   string
  }

  onboard := func(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles("assets/onboard.html"))

    values := r.URL.Query()
    raw_token, ok := values["token"]
    if !ok {
      http.Error(w,  "You forgot to define 'token'", http.StatusInternalServerError)
      return
    }
    token := correct_account_pattern.ReplaceAllString(raw_token[0], "")

    data := PrePageData{
              Link: fmt.Sprintf("%s/onboardonce?token=%s", HOME_URL, token),
            }
    tmpl.Execute(w, data)
  }


// ░░░▄▀▄░█▀▄░░░█▀▀░█▀█░█▀▄░█▀▀░░
// ░░░█\█░█▀▄░░░█░░░█░█░█░█░█▀▀░░
// ░░░░▀\░▀░▀░░░▀▀▀░▀▀▀░▀▀░░▀▀▀░░

  type OnboardPageData struct {
    Account string
    Img     string
  }

  onboardonce := func(w http.ResponseWriter, r *http.Request) {
    tmpl := template.Must(template.ParseFiles("assets/onboardonce.html"))

    values := r.URL.Query()
    raw_token, ok := values["token"]
    if !ok {
      http.Error(w,  "You forgot to define 'token'", http.StatusInternalServerError)
      return
    }
    token := correct_account_pattern.ReplaceAllString(raw_token[0], "")

    db, err := sql.Open("sqlite3", "./data/invites.db")
    if err != nil {
      log.Error("Error opening database")
      http.Error(w,  "Error opening database", http.StatusInternalServerError)
      return
    }
    defer db.Close()

    var account string
    err = db.QueryRow("SELECT account FROM invitees WHERE token=? AND used=0", token).Scan(&account)
    if err != nil {
      log.Warning(fmt.Sprintf("Attempt to read invite not in database: %s", token))
      http.Error(w, "This invite does not exist and this transaction was logged.", http.StatusInternalServerError)
      return
    }

    config, ok := readConfig()
    if !ok {
      log.Warning("Unable to read configuration file.")
      http.Error(w, "There was a problem when trying to read my configuration file. Sorry!", http.StatusInternalServerError)
      return
    }

    foundSecret := ""
    for _, user := range config.Users {
      if user.Name == account {
        if user.Otpsecret == "" {
          log.Warning(fmt.Sprintf("Attempting to read secret for a non-OTP user: %s", account))
          http.Error(w, "TOTP is not enabled for your account. Sorry!", http.StatusInternalServerError)
          return
        }
        foundSecret = user.Otpsecret
        break
      }
      if foundSecret == "" {
        log.Warning(fmt.Sprintf("Unable to find secret for user: %s", account))
        http.Error(w, "It seems this account has vanished. Sorry!", http.StatusInternalServerError)
        return
      }
    }

    var buf []byte
    buf, err = qrcode.Encode(
        infoToLink(
            "totp",
            ISSUER_NAME,
            account,
            foundSecret,
        ),
        qrcode.Medium,
        256)
    if err != nil {
      log.Warning(fmt.Sprintf("Unable to create qr file for token: %s", token))
      http.Error(w,  "There was a problem when trying to create your QR Code. Sorry!", http.StatusInternalServerError)
      return
    }
    img := base64.StdEncoding.EncodeToString(buf)

    statement, _ := db.Prepare("UPDATE invitees SET used=1 WHERE token=?")
    statement.Exec(token)

    log.Notice(fmt.Sprintf("Generated QR Code for account %s", account))

    data := OnboardPageData{
              Account: account,
              Img: img,
            }
    tmpl.Execute(w, data)
  }


  encodeUserSecret := func(c *cli.Context) error {
    // at least 128 bits long after encoding...
    encOtp  := base32.StdEncoding.EncodeToString([]byte(randomString(10)))

    if account := c.String("account"); account != "" {
      config, ok := readConfig()
      if !ok {
        return cli.NewExitError("Unable to read configuration file.", 1)
      }
      modified := false
      for idx, user := range config.Users {
        if user.Name == account {
          config.Users[idx].Otpsecret = encOtp
          modified = true
          break
        }
      }
      if modified {
        writeConfig(config)
      }
    } else {
      fmt.Printf("\nHere is a possible configuration for a LDAP TOTP user:\n\n")
      fmt.Printf("  otpsecret = \"%s\"\n\n", encOtp)
    }
    return nil
  }

  encodeUserPassword := func(c *cli.Context) error {
    if c.NArg() != 1 {
      return cli.NewExitError("Please pass a cleartext password.", 1)
    }
    pass := c.Args().Get(0)
    encPass := sha256.Sum256([]byte(pass))

    if account := c.String("account"); account != "" {
      config, ok := readConfig()
      if !ok {
        return cli.NewExitError("Unable to read configuration file.", 1)
      }
      modified := false
      for idx, user := range config.Users {
        if user.Name == account {
          config.Users[idx].Passsha256 = fmt.Sprintf("%x", encPass)
          modified = true
          break
        }
      }
      if modified {
        writeConfig(config)
      }
    } else {
      fmt.Printf("\nHere is a possible configuration for a LDAP user:\n\n")
      fmt.Printf("  passsha256 = \"%x\"\n\n", encPass)
    }
    return nil
  }



  serve := func(c *cli.Context) error {
    init()

    http.HandleFunc("/onboard", onboard)
    http.HandleFunc("/onboardonce", onboardonce)
    http.HandleFunc("/invite", invite)
    http.HandleFunc("/test", test)

    fs := http.FileServer(http.Dir("/root/Work/ws/assets"))
    http.Handle("/assets/", http.StripPrefix("/assets", fs))

    log.Notice("== Starting web server ==")

    return http.ListenAndServe(":8080", nil)
  }


// ░░░█▄█░█▀█░▀█▀░█▀█░░
// ░░░█░█░█▀█░░█░░█░█░░
// ░░░▀░▀░▀░▀░▀▀▀░▀░▀░░

  app := cli.NewApp()
  app.Version = "0.9.0"
  app.Commands = []cli.Command {
    {
      Name: "serve",
      Usage: "Run web server",
      Action:  serve,
    },
    {
      Name: "secret",
      Usage: "Display or set a secret config string",
      Action:  encodeUserSecret,
      Flags: []cli.Flag {
        cli.StringFlag {
          Name: "account",
          Value: "",
          Usage: "Set account's secret in config file",
        },
      },
    },
    {
      Name: "pass",
      Usage: "Display or set a password config string",
      Action:  encodeUserPassword,
      Flags: []cli.Flag {
        cli.StringFlag {
          Name: "account",
          Value: "",
          Usage: "Set account's password in config file",
        },
      },
    },
  }
  if err := app.Run(os.Args); err != nil {
    log.Fatal(err)
  }
}
