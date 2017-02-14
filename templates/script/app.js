alert('hi');
function createButtons(){
let formInputs = document.querySelectorAll('input');

formInputs.forEach(function(formInputs){
	formInputs.insertAdjacentHTML('beforeend', `<button>DELETE</button>`);
});
}

createButtons();