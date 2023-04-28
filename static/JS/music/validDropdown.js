var selectedValues = {};
		function onDropdownChange(dropdownId) {
			var selectedValue = document.getElementById(dropdownId).value;
			if (selectedValue in selectedValues && selectedValues[selectedValue] !== dropdownId) {
				// Reset the selected option
				document.getElementById(dropdownId).value = "";
				alert("This option has already been selected in another dropdown!");
			} else {
                for(let key in selectedValues){
                    if(selectedValues[key] === dropdownId){
                        delete selectedValues[key];
                        break;
                    }
                }
				selectedValues[selectedValue] = dropdownId;
                const filepath =  "/static/soundEffects/" + selectedValue + ".mp3";
                var audio = document.getElementById("myAudio");
                audio.src = filepath;
                audio.play();
			}
		}