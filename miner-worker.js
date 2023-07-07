"use strict";

function rawToHex(raw) {
  var hex = "";
  var hexChars = "0123456789abcdef";
  for (var i = 0; i < raw.length; i++) {
    var c = raw.charCodeAt(i);
    hex += hexChars.charAt((c >>> 4) & 0x0f) + hexChars.charAt(c & 0x0f);
  }
  return hex;
}

function sha1Raw(raw) {
  return binaryToRaw(sha1Binary(rawToBinary(raw), raw.length * 8));
}

function binaryToRaw(bin) {
  var raw = "";
  for (var i = 0, il = bin.length * 32; i < il; i += 8) {
    raw += String.fromCharCode((bin[i >> 5] >>> (24 - (i % 32))) & 0xff);
  }
  return raw;
}

function sha1Binary(bin, len) {
  bin[len >> 5] |= 0x80 << (24 - (len % 32));
  bin[(((len + 64) >> 9) << 4) + 15] = len;

  var w = new Array(80);
  var a = 1732584193;
  var b = -271733879;
  var c = -1732584194;
  var d = 271733878;
  var e = -1009589776;

  for (var i = 0, il = bin.length; i < il; i += 16) {
    var _a = a;
    var _b = b;
    var _c = c;
    var _d = d;
    var _e = e;

    for (var j = 0; j < 80; j++) {
      if (j < 16) {
        w[j] = bin[i + j];
      } else {
        w[j] = _rotateLeft(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1);
      }
      var t = _add(
        _add(_rotateLeft(a, 5), _ft(j, b, c, d)),
        _add(_add(e, w[j]), _kt(j))
      );
      e = d;
      d = c;
      c = _rotateLeft(b, 30);
      b = a;
      a = t;
    }

    a = _add(a, _a);
    b = _add(b, _b);
    c = _add(c, _c);
    d = _add(d, _d);
    e = _add(e, _e);
  }
  return [a, b, c, d, e];
}

function _add(x, y) {
  var lsw = (x & 0xffff) + (y & 0xffff);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xffff);
}


function _rotateLeft(n, count) {
  return (n << count) | (n >>> (32 - count));
}


function _ft(t, b, c, d) {
  if (t < 20) {
    return (b & c) | (~b & d);
  } else if (t < 40) {
    return b ^ c ^ d;
  } else if (t < 60) {
    return (b & c) | (b & d) | (c & d);
  } else {
    return b ^ c ^ d;
  }
}

function _kt(t) {
  if (t < 20) {
    return 1518500249;
  } else if (t < 40) {
    return 1859775393;
  } else if (t < 60) {
    return -1894007588;
  } else {
    return -899497514;
  }
}

function rawToBinary(raw) {
  var binary = new Array(raw.length >> 2);
  for (var i = 0, il = binary.length; i < il; i++) {
    binary[i] = 0;
  }
  for (i = 0, il = raw.length * 8; i < il; i += 8) {
    binary[i >> 5] |= (raw.charCodeAt(i / 8) & 0xff) << (24 - (i % 32));
  }
  return binary;
}

function stringToRaw(string) {
  var raw = "",
    x,
    y;
  var i = -1;
  var il = string.length;
  while (++i < il) {
    x = string.charCodeAt(i);
    y = i + 1 < il ? string.charCodeAt(i + 1) : 0;
    if (0xd800 <= x && x <= 0xdbff && 0xdc00 <= y && y <= 0xdfff) {
      x = 0x10000 + ((x & 0x03ff) << 10) + (y & 0x03ff);
      ++i;
    }
    if (x <= 0x7f) {
      raw += String.fromCharCode(x);
    } else if (x <= 0x7ff) {
      raw += String.fromCharCode(0xc0 | ((x >>> 6) & 0x1f), 0x80 | (x & 0x3f));
    } else if (x <= 0xffff) {
      raw += String.fromCharCode(
        0xe0 | ((x >>> 12) & 0x0f),
        0x80 | ((x >>> 6) & 0x3f),
        0x80 | (x & 0x3f)
      );
    } else if (x <= 0x1fffff) {
      raw += String.fromCharCode(
        0xf0 | ((x >>> 18) & 0x07),
        0x80 | ((x >>> 12) & 0x3f),
        0x80 | ((x >>> 6) & 0x3f),
        0x80 | (x & 0x3f)
      );
    }
  }
  return raw;
}

function hmacRaw(key, data) {
  var binaryKey = rawToBinary(key);
  if (binaryKey.length > 16) {
    binaryKey = sha1Binary(binaryKey, key.length * 8);
  }
  var ipad = new Array(16);
  var opad = new Array(16);
  for (var i = 0; i < 16; i++) {
    ipad[i] = binaryKey[i] ^ 0x36363636;
    opad[i] = binaryKey[i] ^ 0x5c5c5c5c;
  }
  var hash = sha1Binary(ipad.concat(rawToBinary(data)), 512 + data.length * 8);
  return binaryToRaw(sha1Binary(opad.concat(hash), 512 + 160));
}

function sha1(toHash) {
  return rawToHex(sha1Raw(stringToRaw(toHash)));
}

function roundTo(precision, value) {
  var power_of_ten = 10 * (precision * precision);
  return Math.round(value * power_of_ten) / power_of_ten;
}

let XMLHttpFactories = [
  function () {
    return new XMLHttpRequest();
  }, 
  function () {
    return new ActiveXObject("Msxml3.XMLHTTP");
  },
  function () {
    return new ActiveXObject("Msxml2.XMLHTTP.6.0");
  },
  function () {
    return new ActiveXObject("Msxml2.XMLHTTP.3.0");
  },
  function () {
    return new ActiveXObject("Msxml2.XMLHTTP");
  },
  function () {
    return new ActiveXObject("Microsoft.XMLHTTP");
  },
];

let requestApi = false;
for (let i = 0; i < XMLHttpFactories.length; i++) {
  try {
    requestApi = XMLHttpFactories[i]();
  } catch (e) {
    continue;
  }
  break;
}

function httpGet(theUrl) {
  requestApi.open("GET", theUrl, false);
  requestApi.send(null);
  return requestApi.responseText;
}

function httpPost(theUrl) {
  requestApi.open("POST", theUrl, false);
  requestApi.send(null);
  return requestApi.responseText;
}

let shouldRun = false;
let username;
let key;
let useragent;
const base_url = "http://51.15.127.80";

onmessage = function (event) {
  username = event.data.username;
  key = event.data.key;
  useragent = event.data.userAgent;

  if (event.data.action === "mine") {
    console.log("mine");
    shouldRun = true;
    mineLoop();
  } else if (event.data.action === "stop") {
    console.log("stop");
    shouldRun = false;
  }
};

function mineLoop() {
  if (shouldRun) {
    console.log("running");
    try {
      const job = httpGet(
        base_url +
          "/legacy_job?u=" +
          username +
          "&i=" +
          useragent +
          "&nocache=" +
          new Date().getTime()
      );

      console.log("Start Mining");
      const last_block_hash = job.split(",")[0];
      const expected_hash = job.split(",")[1];
      const difficulty = job.split(",")[2];

      postMessage({
        type: "progress",
        data: {
          status: "Trying ...",
          lastHash: last_block_hash,
          expected: expected_hash,
          diff: difficulty,
        },
      });

      const timeStart = new Date().getTime();
      let result = 0;
      let current_hash;
      for (; result < difficulty * 100; result++) {
        current_hash = sha1(last_block_hash + result);
        if (current_hash == expected_hash) {
          console.log("Found Hash");
          const timeEnd = new Date().getTime();
          const timeDiff = timeEnd - timeStart;
          const hashRate = roundTo(2, (result / timeDiff) * 1000);

          const feedback = `Hash found: ${current_hash}\nResult: ${result}\nTime taken: ${timeDiff} ms\nHash rate: ${hashRate} hashes/s`;
          console.log(feedback);

          postMessage({
            type: "progress",
            data: {
              status: "FOUND !",
              lastHash: last_block_hash,
              expected: expected_hash,
              diff: difficulty,
            },
          });

          const response = httpPost(
            base_url +
              "/legacy_job?u=" +
              username +
              "&r=" +
              result +
              "&k=" +
              key +
              "&s=Duino Miner JS" +
              "&j=" +
              expected_hash +
              "&i=" +
              useragent +
              "&h=" +
              hashRate +
              "&b=" +
              timeDiff +
              "&nocache=" +
              new Date().getTime()
          );
          postMessage({
            type: "result",
            data: { resp: feedback, validated: response },
          });
          break;
        } else {
        }
      }
    } catch (error) {
      // Handle any errors and send the error message to the main thread
      postMessage({ type: "error", data: { message: error.message } });
    }
    postMessage({ type: "done" });
  }
}
