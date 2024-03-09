var exampleSocket;
var liveuserSocket;
displayView = function () {
  token = localStorage.getItem("loginusertocken");
  if (token) {
    already_login();
  }
  else {
    document.getElementById('content').innerHTML = document.getElementById('welcomeview').innerHTML;
  }
};



window.onload = function () {
  displayView();
};



function checkpw(id1, id2, message_id, button) {
  if (document.getElementById(id1).value == document.getElementById(id2).value) {
    document.getElementById(message_id).innerHTML = '';
    document.getElementById(button).disabled = false;
  } else {
    document.getElementById(message_id).style.color = 'red';
    document.getElementById(message_id).innerHTML = 'Password not matching';
    document.getElementById(button).disabled = true;
  }
}


function login(formdata) {
  var email = formdata.login_email.value;
  var password = formdata.login_password.value;
  var req = new XMLHttpRequest();
  var url = "/sign_in";
  var send = { username: email, password: password }
  req.open("POST", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.send(JSON.stringify(send));

  req.onload = function () {
    if (this.readyState == 4) {
      var res_data = JSON.parse(this.response);
      if (res_data.success == "true" && this.status == 200) {
        localStorage.setItem("loginusertocken", res_data.data)
        document.getElementById('content').innerHTML = document.getElementById('logged_in').innerHTML;
        element = document.getElementById("tabs1");
        display_tab(element);
        set_user_data();
        read_wall();
        makeWebSocket(email);

      } else {
        popupErrorMsg(this.status, res_data.message)
      }
    }
  };
}


function makeWebSocket(email) {
  if (exampleSocket && exampleSocket.connected) {
    console.log('socket.io is connected.')
    return;
  } else {
    console.log('socket.io is not connected.')
    exampleSocket = new WebSocket(
      "ws://127.0.0.1:5000/check_login"
    );
    exampleSocket.onmessage = (event) => {
      console.log("Listening...");
      console.log(event.data);
      if (document.getElementById('online_users') != null) {
        if (event.data == 1) {
          c = localStorage.getItem("livecount");
          livecount = ++c;
          document.getElementById('online_users').innerHTML = 'Online Users :' + livecount;
        } else {
          c = localStorage.getItem("livecount");
          livecount = --c;
          document.getElementById('online_users').innerHTML = 'Online Users :' + livecount;
        }
      }

      if(event.data=="searched" && localStorage.getItem("currentTab")=="tabs4"){
        getViews();
      }
      if(event.data=="wallpost" && localStorage.getItem("currentTab")=="tabs4"){
        getMessageCount();
      }
      
    };
    exampleSocket.onclose = (event) => {
      console.log("Closing...");
      // localStorage.clear();     
      document.getElementById('content').innerHTML = document.getElementById('welcomeview').innerHTML;
    };
    exampleSocket.onopen = (event) => {
      console.log("Sending...");
      exampleSocket.send(email);
    };
  }


}



function saveContact(formData) {
  var firstname = formData.firstname.value;
  var familyname = formData.familyname.value;
  var gender = formData.gender.value;
  var city = formData.city.value;
  var country = formData.country.value;
  var email = formData.emailsignup.value;
  var password = formData.passwordsignup.value;
  if (firstname != "" && familyname != "" && gender != "" && country != "" && email != "" && validateEmail(email) && password != "" && (password.length > 4)) {
    var contact = {
      firstname: firstname,
      familyname: familyname,
      gender: gender,
      city: city,
      country: country,
      email: email,
      password: password
    };

    //var message = serverstub.signUp(contact);
    var req = new XMLHttpRequest();
    var url = "/sign_up";
    req.open("POST", url, true);
    req.setRequestHeader("Content-type", "application/json");
    req.send(JSON.stringify(contact));

    req.onload = function () {
      var res_data = JSON.parse(this.response);
      if (this.readyState == 4) {
        if (res_data.success == "true" && this.status == 201) {
          document.getElementById("sign-up-form").reset();
          document.getElementById('message').innerHTML = res_data.message;
          document.getElementById('message').style.color = 'green';
        } else {
          popupErrorMsg(this.status, res_data.message);
        }
      } else {
        popupErrorMsg(this.status, res_data.message);
        // document.getElementById('message').innerHTML = res_data.message;
        // document.getElementById('message').style.color = 'red';
      }
    };

  } else {
    document.getElementById('message').innerHTML = "Please fill mandatory data.";
    document.getElementById('message').style.color = 'red';
  }
}



function validateEmail(email) {
  var re = /\S+@\S+\.\S+/;
  return re.test(email);
}

var already_login = function () {
  token = localStorage.getItem("loginusertocken");
  console.log("already_login", token)

  var req = new XMLHttpRequest();
  var url = "/get_user_data_by_token";
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    if (this.readyState == 4) {
      var res_data = JSON.parse(this.response);
      if (this.status == 200 && res_data.success == "true") {
        userdata = res_data.data;
        if (userdata && userdata.email != null) {
          makeWebSocket(userdata.email);
          document.getElementById('content').innerHTML = document.getElementById('logged_in').innerHTML;
          showCurrentTab();
          var currenttab = localStorage.getItem("currentTab");
          if (currenttab && currenttab != null && document.getElementById(currenttab) != null) {
            display_tab(document.getElementById(currenttab));
            //document.getElementById(currenttab).style.display = 'block';
          } else {
            display_tab(document.getElementById("tabs-1"));
            //document.getElementById("tabs-1").style.display = 'block';
          }
          set_user_data();
          read_wall();
        } else {
          console.log(res_data.message);
        }
      } else {
        document.getElementById('content').innerHTML = document.getElementById('welcomeview').innerHTML;
        console.log(res_data.message);
      }
    }
  };

}



var display_tab = function (element) {
  getNumberofOnlineUsers();
  var tab_panels = document.getElementsByClassName('tab_panel');
  for (var i = 0; i < tab_panels.length; i++) {
    tab_panels[i].style.display = 'none';
    if (document.getElementById("tabs" + (i + 1)).classList.contains("activeBtn")) {
      document.getElementById("tabs" + (i + 1)).classList.remove("activeBtn");
    }
  }

  var currenttab = localStorage.getItem("currentTab");
  if (currenttab == "tabs4") {
    Chart.helpers.each(Chart.instances, function (instance) {
      instance.destroy();
    });
  }

  if (document.getElementById(element.id)) {
    document.getElementById(element.id).classList.add("activeBtn");
    if (element.id == "tabs4" || element.id == "tabs-4") {
      getViews();
      getMessageCount();
    }
  }

  if (element.id.includes("-")) {
    var tabContentIdToShow = element.id;
  } else {
    var tabContentIdToShow = element.id.replace(/(\d)/g, '-$1');
  }
  localStorage.setItem("currentTab", element.id);
  document.getElementById(tabContentIdToShow).style.display = 'block';
}



function showCurrentTab() {
  var tabContentIdToShow = localStorage.getItem("currentTab");
  if (tabContentIdToShow && tabContentIdToShow != null) {
    var tab_panels = document.getElementsByClassName('tab_panel');
    for (var i = 0; i < tab_panels.length; i++) {
      tab_panels[i].style.display = 'none';
      if (document.getElementById("tabs" + (i + 1)).classList.contains("activeBtn")) {
        document.getElementById("tabs" + (i + 1)).classList.remove("activeBtn");
      }
    }
    var tabbuttonid = tabContentIdToShow.replace("-", "")
    if (document.getElementById(tabbuttonid)) {
      document.getElementById(tabbuttonid).classList.add("activeBtn");
    }
    document.getElementById(tabContentIdToShow).style.display = 'block';
  } else {
    document.getElementById('content').innerHTML = document.getElementById('welcomeview').innerHTML;
    if (document.getElementById("tabs1")) {
      document.getElementById("tabs1").classList.add("activeBtn");
    }

  }

}

var changing_password = function () {
  token = localStorage.getItem("loginusertocken");
  old_PSW = document.getElementById("change_old_psw").value;
  new_PSW = document.getElementById("change_new_psw").value;
  var send = { oldpassword: old_PSW, newpassword: new_PSW }
  // var msg = serverstub.changePassword(token,old_PSW,new_PSW);
  var req = new XMLHttpRequest();
  var url = "/change_password";
  req.open("PUT", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader('Authorization', token);
  req.send(JSON.stringify(send));

  req.onload = function () {
    var res_data = JSON.parse(this.response);
    if (this.readyState == 4) {
      if (this.status == 200 && res_data.success == "true") {
        document.getElementById('span_test_4').innerHTML = res_data.message;
        document.getElementById('span_test_4').style.color = "green";
        document.getElementById("change_old_psw").value = "";
        document.getElementById("change_new_psw").value = "";
        document.getElementById("repeat_new_psw").value = "";
      } else {
        popupErrorMsg(this.status, res_data.message)
        // document.getElementById('span_test_4').innerHTML =res_data.message;
        // document.getElementById('span_test_4').style.color="red";
      }
    }
    // else{
    //   document.getElementById('span_test_4').innerHTML =res_data.message;
    //   document.getElementById('span_test_4').style.color="red";
    // }
  };
}


var signOut = function () {
  token = localStorage.getItem("loginusertocken");
  var req = new XMLHttpRequest();
  var url = "/sign_out";
  req.open("DELETE", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();
  req.onload = function () {
    var res_data = JSON.parse(this.response);
    if (this.readyState == 4) {
      if (res_data.success == "true" && this.status == 200) {
        c = localStorage.getItem("livecount");
        localStorage.setItem("livecount", --c);
        document.getElementById('content').innerHTML = document.getElementById('welcomeview').innerHTML;
      } else {
        popupErrorMsg(this.status, res_data.message)
      }
    }
  }
}

var set_user_data = function () {
  token = localStorage.getItem("loginusertocken");
  var req = new XMLHttpRequest();
  var url = "/get_user_data_by_token";
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    if (this.readyState == 4) {
      var res_data = JSON.parse(this.response);
      if (res_data.success == "true" && this.status == 200) {
        userdata = res_data.data;
        if (document.getElementById("personal-error-msg"))
          document.getElementById("personal-error-msg").innerHTML = "";
        document.getElementById("fullName").innerHTML = userdata.firstname+" "+userdata.familyname;
        document.getElementById("email_output").innerHTML = userdata.email;
        document.getElementById("name_output").innerHTML = userdata.firstname;
        document.getElementById("familyname_output").innerHTML = userdata.familyname;
        document.getElementById("gender_output").innerHTML = userdata.gender;
        document.getElementById("city_output").innerHTML = userdata.city;
        document.getElementById("country_output").innerHTML = userdata.country;
      } else {
        popupErrorMsg(this.status, res_data.message)
        // document.getElementById("personal-error-msg").innerHTML = res_data.message;
      }
    } else {
      document.getElementById("personal-error-msg").innerHTML = this.message;
    }
  }
}

var user_data_2 = function () {
  document.getElementById("search-error").innerHTML = "";
  token = localStorage.getItem("loginusertocken");
  email = document.getElementById("search_member").value;
  document.getElementById("theTextarea").innerHTML = "";

  if (email != "") {
    // var getuser_output_other = serverstub.getUserDataByEmail(token,email);
    var req = new XMLHttpRequest();
    var url = "/get_user_data_by_email/" + email;
    req.open("GET", url, true);
    req.setRequestHeader("Content-type", "application/json");
    req.setRequestHeader("Authorization", token);
    req.send();

    req.onload = function () {
      var res_data = JSON.parse(this.response);
      if (this.readyState == 4) {
        if (res_data.success == "true" && this.status == 200) {
          document.getElementById("fullName").innerHTML = res_data.data.firstname+" "+res_data.data.familyname;
          document.getElementById("email_output_2").innerHTML = res_data.data.email;
          document.getElementById("name_output_2").innerHTML = res_data.data.firstname;
          document.getElementById("familyname_output_2").innerHTML = res_data.data.familyname;
          document.getElementById("gender_output_2").innerHTML = res_data.data.gender;
          document.getElementById("city_output_2").innerHTML = res_data.data.city;
          document.getElementById("country_output_2").innerHTML = res_data.data.country;
          read_wall_2();
        } else {
          popupErrorMsg(this.status, res_data.message)
          // document.getElementById("search-error").innerHTML = res_data.message;
          // document.getElementById("search-error").style.color="red";
        }
      }
    }
  } else {
    document.getElementById("search-error").innerHTML = "Please select a user.";
    document.getElementById("search-error").style.color = "red";
  }

}

var post_to_wall = function (status = false) {
  document.getElementById("wall-post-error-1").innerHTML = "";
  token = localStorage.getItem("loginusertocken");
  // email = JSON.parse(localStorage.getItem("loggedinusers"))[token];
  message = document.getElementById("wall_thoughts").value;

  if (status && message == "") {
    document.getElementById("wall-post-error-1").innerHTML = "Please type a message.";
    document.getElementById('wall-post-error-1').style.color = "red";
  } else {
    // var wall_data = serverstub.postMessage(token, message, email);
    var req = new XMLHttpRequest();
    var url = "/post_message";
    var send = { message: message }
    req.open("POST", url, true);
    req.setRequestHeader("Content-type", "application/json");
    req.setRequestHeader("Authorization", token);
    req.send(JSON.stringify(send));

    req.onload = function () {
      var res_data = JSON.parse(this.response);
      if (this.readyState == 4) {
        if (res_data.success == "true" && this.status == 200) {
          document.getElementById("wall_thoughts").value = "";
          read_wall();
        } else {
          popupErrorMsg(this.status, res_data.message)
          // document.getElementById("wall-post-error-1").innerHTML =res_data.message;
          // document.getElementById('wall-post-error-1').style.color="red";
        }
      }
      // else{
      //   document.getElementById("wall-post-error-1").innerHTML =res_data.message;
      //   document.getElementById('wall-post-error-1').style.color="red";
      // }

    }
  }
}

var read_wall = function () {
  document.getElementById("theTextarea").innerHTML = "";
  document.getElementById("wall-post-error-1").innerHTML = "";

  token = localStorage.getItem("loginusertocken");
  //user_output = serverstub.getUserMessagesByToken(token);
  var req = new XMLHttpRequest();
  var url = "/get_user_messages_by_token";
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    var res_data = JSON.parse(this.response);
    if (this.readyState == 4 && this.status == 200) {
      if (res_data.success == "true") {
        userdata = res_data.data;
        if (userdata) {
          var text = ""
          for (i = 0; i < userdata.length; i++) {
            if (userdata[i].content != "") {
              text += "<b>" + userdata[i].writer + "</b>" + ":" + userdata[i].content + "<br><br>";
            }
          }
          document.getElementById("theTextarea").innerHTML = text;
        } else {
          console.log(res_data.message);
        }
      } else {
        console.log(res_data.message);
      }
    }
  };
}

var post_to_wall_2 = function () {
  document.getElementById("wall-post-error").innerHTML = "";
  token = localStorage.getItem("loginusertocken");
  var email = document.getElementById("search_member").value;
  var message = document.getElementById("wall_thoughts_2").value;

  if (email != "") {
    if (message != "") {
      var req = new XMLHttpRequest();
      var url = "/post_message";
      var send = { email: email, message: message }
      req.open("POST", url, true);
      req.setRequestHeader("Content-type", "application/json");
      req.setRequestHeader("Authorization", token);
      req.send(JSON.stringify(send));

      req.onload = function () {
        var res_data = JSON.parse(this.response);
        if (this.readyState == 4) {
          if (res_data.success == "true" && this.status == 200) {
            document.getElementById("wall_thoughts_2").value = "";
            read_wall_2();
          } else {
            popupErrorMsg(this.status, res_data.message)
            // document.getElementById("wall-post-error-1").innerHTML =res_data.message;
            // document.getElementById('wall-post-error-1').style.color="red";
          }
        } else {
          popupErrorMsg(this.status, res_data.message)
          // document.getElementById("wall-post-error").innerHTML =wall_data.message;
          // document.getElementById('wall-post-error').style.color="red";
        }
      }
    } else {
      document.getElementById("wall-post-error").innerHTML = "Please type a message.";
      document.getElementById('wall-post-error').style.color = "red";
    }
  } else {
    document.getElementById("wall-post-error").innerHTML = "Please Select a User.";
    document.getElementById('wall-post-error').style.color = "red";
  }
}

var read_wall_2 = function () {
  document.getElementById("theTextarea_2").innerHTML = "";
  document.getElementById("wall-post-error").innerHTML = "";
  token = localStorage.getItem("loginusertocken");
  var email = document.getElementById("search_member").value;

  var req = new XMLHttpRequest();
  var url = "/get_user_messages_by_email/" + email;
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    var res_data = JSON.parse(this.response);
    if (this.readyState == 4 && this.status == 200) {
      if (res_data.success == "true") {
        user_output = res_data.data;
        var text = ""
        for (i = 0; i < user_output.length; i++) {
          if (user_output[i].content != "") {
            text += "<b>" + user_output[i].writer + "</b>" + ":" + user_output[i].content + "<br><br>";
          }
        }
        document.getElementById("theTextarea_2").innerHTML = text;
      } else {
        document.getElementById("theTextarea_2").innerHTML = "";
      }
    }
  };
  // var user_message = serverstub.getUserMessagesByEmail(token, email);


}

function popupErrorMsg(status, message) {
  if (status == 400 && message == "invaliddata") {
    alert("The entered username or password is incorrect! Please enter your username and password.!");
  } else if (status == 400 && message == "nosignup") {
    alert("The entered username does not exist! Please sign up.!");
  } else if (status == 400 && message == "emptydata") {
    alert("The entered data empty or incorrect.! Please try again.");
  } else if (status == 400 && message == "invalidemail") {
    alert("Email address is incorrect.! Please enter valid email.");
  } else if (status == 500) {
    alert("Something went wrong! Please try again.");
  } else if (status == 405) {
    alert("Request is not allowed! Please try again.”");
  } else if (status == 401 && message == "") {
    alert("Authentication failed.! Please try again.”");
  } else if (status == 409 && message == "userexist") {
    alert("The username is already taken! Please try another one!");
  } else if (status == 404) {
    alert("Incorrect request or data have been deleted.");
  } else if (status == 400 && message == "passwordnotmatch") {
    alert("Old password is incorrect.!Please try again.");
  } else if (status == 400 && message == "emailnotfound") {
    alert("Incorrect user or user have been deleted.! Please try again.");
  } else if (status == 400 && message == "nouserfound") {
    alert("The entered username does not exist! Please try again!");
  } else if (status == 400 && message == "nomessages") {
    alert("Incorrect message id! The message may have been deleted!");
  }

}

function getViews() {
  token = localStorage.getItem("loginusertocken");
  var req = new XMLHttpRequest();
  var url = "/get_profile_views";
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    if (this.readyState == 4) {
      var res_data = JSON.parse(this.response);
      if (res_data.success == "true" && this.status == 200) {
        views = res_data.data;
        let today = new Date();
        let lastweekfistday = new Date(today.getDate() - 6);
        todayviews = 0;
        weekviews = 0;
        monthviews = 0;
        for (i = 0; i < views.length; i++) {
          viewdate = new Date(views[i].date);
          if (today.getDate() == viewdate.getDate()) {
            todayviews = todayviews + views[i].views;
          }
          if (today.getMonth() == viewdate.getMonth()) {
            monthviews = monthviews + views[i].views;
          }
          if (lastweekfistday.getDate() <= viewdate.getDate()) {
            weekviews = weekviews + views[i].views;
          }
        }
        totalviews = [monthviews, weekviews, todayviews]
        loadchart1(totalviews);
      } else {
        console.log(res_data.message)
        return [0, 0, 0];
      }
    } else {
      console.log(this.message)
      // document.getElementById("personal-error-msg").innerHTML = this.message;
      return [0, 0, 0];
    }
  }
}

let chart1;
function loadchart1(data) {
  const ctx = document.getElementById('myChart').getContext("2d");
  if (chart1) chart1.destroy();
  chart1 = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['This Month', 'This Week', 'ToDay'],
      datasets: [{
        label: 'Number of Profile Views',
        data: data,
        borderWidth: 1
      }]
    },
    options: {
      scales: {
        y: {
          beginAtZero: true
        }
      }
    }
  });
}

function getMessageCount() {
  token = localStorage.getItem("loginusertocken");
  //user_output = serverstub.getUserMessagesByToken(token);
  var req = new XMLHttpRequest();
  var url = "/get_user_messages_by_token";
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    var res_data = JSON.parse(this.response);
    if (this.readyState == 4 && this.status == 200) {
      if (res_data.success == "true") {
        userdata = res_data.data;
        if (userdata) {
          var counts = {};
          for (i = 0; i < userdata.length; i++) {
            var msges = 1;
            // if(counts.length>0){
            for (k in counts) {
              if (userdata[i].writer == k) {
                msges = counts[k] + msges;
              }
            }
            // }
            counts[userdata[i].writer] = msges;
          }
          chart2(counts);
        } else {
          console.log(res_data.message);
        }
      } else {
        console.log(res_data.message);
      }
    }
  };
}

let chart;
function chart2(counts) {
  const ctx2 = document.getElementById('myChart2').getContext("2d");
  if (chart) chart.destroy();
  chart = new Chart(ctx2, {
    type: 'pie',
    data: {
      labels: Object.keys(counts),
      datasets: [{
        label: 'Number of Post',
        data: Object.values(counts)
      }]
    },
    options: {
      maintainAspectRatio: false,
      responsive: true,
      plugins: {
        legend: {
          position: 'top',
        },
        title: {
          display: true,
          text: 'Post Summery of Wall'
        }
      }
    }
  });
}

function getNumberofOnlineUsers() {
  token = localStorage.getItem("loginusertocken");
  //user_output = serverstub.getUserMessagesByToken(token);
  var req = new XMLHttpRequest();
  var url = "/get_online_users";
  req.open("GET", url, true);
  req.setRequestHeader("Content-type", "application/json");
  req.setRequestHeader("Authorization", token);
  req.send();

  req.onload = function () {
    var res_data = JSON.parse(this.response);
    if (this.readyState == 4 && this.status == 200) {
      if (res_data.success == "true") {
        localStorage.setItem("livecount", res_data.data);
        document.getElementById('online_users').innerHTML = 'Online Users :' + res_data.data;
      } else {
        document.getElementById('online_users').innerHTML = 'Online Users : 0';
        console.log(res_data.message);
      }
    } else {
      document.getElementById('online_users').innerHTML = 'Online Users :0';
      console.log(res_data.message);
    }
  };
}