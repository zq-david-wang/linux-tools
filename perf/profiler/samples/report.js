function isNumber(n) {
  return !isNaN(parseFloat(n)) && isFinite(n);
}

function setFontSize(el) {
    var fontSize = el.val();
    
    if ( isNumber(fontSize) && fontSize >= 0.5 ) {
      $('body').css({ fontSize: fontSize + 'em' });
    } else if ( fontSize ) {
      el.val('1');
      $('body').css({ fontSize: '1em' });  
    }
}

$(function() {
  
  $('#fontSize')
    .bind('change', function(){ setFontSize($(this)); })
    .bind('keyup', function(e){
      if (e.keyCode == 27) {
        $(this).val('1');
        $('body').css({ fontSize: '1em' });  
      } else {
        setFontSize($(this));
      }
    });
  
  $(window)
    .bind('keyup', function(e){
      if (e.keyCode == 27) {
        $('#fontSize').val('1');
        $('body').css({ fontSize: '1em' });  
      }
    });
  
});
