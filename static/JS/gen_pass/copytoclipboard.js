function copyToClipboard() {
      var copyText = document.getElementById("generated_password");
      copyText.select();
      copyText.setSelectionRange(0, 99999);
      document.execCommand("copy");
      alert("Copied the password: " + copyText.value);
   }