const slider = document.getElementById("length");
            const output = document.getElementById("length-value");
            output.innerHTML = slider.value;

            slider.oninput = function() {
                output.innerHTML = this.value;
            }