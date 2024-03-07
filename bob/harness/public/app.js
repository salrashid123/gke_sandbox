

function checkStatus() {
    fetch('/check')
      .then(function (response) {
        if (response.status !== 200) {
          console.log(
            'Looks like there was a problem. Status Code: ' + response.status
          );
          return;
        }
        response.json().then(function (data) {
          console.log(data);
          document.getElementById("json").innerHTML = JSON.stringify(data, undefined, 2);
        });
      })
      .catch(function (err) {
        console.log('Fetch Error :-S', err);
      });
  }
  
  function predict() {
    fetch('/predict',{
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ "reviews": [document.getElementById("review1").value,document.getElementById("review2").value,document.getElementById("review3").value]
        })        
    })
      .then(function (response) {
        if (response.status !== 200) {
          console.log(
            'Looks like there was a problem. Status Code: ' + response.status
          );
          return;
        }
        response.json().then(function (data) {
          console.log(data);
          document.getElementById("result1").value = data[0];
          document.getElementById("result2").value = data[1];
          document.getElementById("result3").value = data[2];
        });
      })
      .catch(function (err) {
        console.log('Fetch Error :-S', err);
      });
  }
  
