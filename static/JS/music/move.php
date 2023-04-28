$(document).ready(function() {
      // Move focus to next text box when a digit is entered
      $('.passcode-input').keyup(function() {
        if ($(this).val().length == $(this).attr('maxlength')) {
          $(this).next('.passcode-input').focus();
        }
      });
    });