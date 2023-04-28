var usedCodes = {};
            function isNumeric(str) {
                return !isNaN(parseFloat(str)) && isFinite(str);
            }
            function onCodeChange(codeId){
                var code = document.getElementsById(codeId).value;
                if(code === ''){
                    for(let key in usedCodes){
                        if(usedCodes[key] === codeId){
                            delete usedCodes[key];
                            break;
                        }
                    }
                }
                else if(!isNumeric(code)){
                    document.getElementById(codeId).value = "";
                    alert("Code should be a number [0-9]")
                }
                else if (code in usedCodes && usedCodes[code] !== codeId){
                    document.getElementById(codeId).value = "";
                    alert("You have already chosen this number")
                }
                else {
                    for(let key in usedCodes){
                        if(usedCodes[key] === codeId){
                            delete usedCodes[key];
                            break;
                        }
                    }
                    usedCodes[code] = codeId;
                }

            }