var context = JSON.parse('{{ context_data|escapejs }}');
     audio = document.getElementById('myAudio');
    const f1 = context['f1'];
    const f2 = context['f2'];
    const f3 = context['f3'];
    var sources = [f1, f2, f3];
    var index = 0;

    function playAudio() {
      if (index < sources.length) {
        audio.src = "/static/soundEffects/" + sources[index] + ".mp3";
        audio.play();
        index++;
        audio.addEventListener('ended', playAudio);
      }
      else
          index=0;
    }
