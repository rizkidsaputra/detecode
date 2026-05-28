const express = require("express");
const { exec } = require("child_process");
const fs = require("fs");
const app = express();

app.get("/user", (req, res) => {
  db.query("SELECT * FROM users WHERE id = " + req.query.id);
  exec(req.query.cmd);
  fs.readFile(req.query.file, "utf8", (err, data) => res.send(data));
  eval(req.body.code);
  fetch(req.query.url).then(r => r.text()).then(t => res.send(t));
});

document.getElementById("result").innerHTML = location.hash;
