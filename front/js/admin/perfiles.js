infoForm={};    // para la tabla.
tabla = document.getElementById("tablaperfiles"); // tabla 

function consultar_perfil(){
    axios({
        methods: 'GET',
        url: 'http://127.0.0.1:5000/perfiles',

    }).then(function (response){

        for (let i = 0; i < response.data.length; i++){

            let nuevaFila = tabla.insertRow(tabla.length);

            cell0 = nuevaFila.insertCell(0);
            cell0.innerHTML = response.data[i].perfilid;

            cell1 = nuevaFila.insertCell(1);
            cell1.innerHTML = response.data[i].perfil;

            cell2 = nuevaFila.insertCell(2);
            cell2.innerHTML = response.data[i].descripcion;

        }

    }).catch(err => console.log('Error: ', err))

}
function mostrarFormulario() {
    // Mostrar el formulario al hacer clic en el botón
    document.getElementById("formulario").style.display = "block";
}
