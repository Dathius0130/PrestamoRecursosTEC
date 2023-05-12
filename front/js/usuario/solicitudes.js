infoForm={};    // para la tabla.
tabla = document.getElementById("tablasolicitudes"); // tabla 

function consultar_solicitudes(){
    axios({
        methods: 'GET',
        url: 'http://127.0.0.1:5000/solicitudes',

    }).then(function (response){

        for (let i = 0; i < response.data.length; i++){

            let nuevaFila = tabla.insertRow(tabla.length);

            cell0 = nuevaFila.insertCell(0);
            cell0.innerHTML = response.data[i].solicitud;

            cell1 = nuevaFila.insertCell(1);
            cell1.innerHTML = response.data[i].usuario;

            cell2 = nuevaFila.insertCell(2);
            cell2.innerHTML = response.data[i].item;

            cell3 = nuevaFila.insertCell(3);
            cell3.innerHTML = response.data[i].fecha;

            cell4 = nuevaFila.insertCell(4);
            cell4.innerHTML = response.data[i].estado;

            cell5 = nuevaFila.insertCell(5);
            cell5.innerHTML = response.data[i].observacion;

            cell6 = nuevaFila.insertCell(6);
            cell6.innerHTML = `<a class="btn btn-warning mx-5 " onClick="onEdit(this)">Editar</a>`;
        }

    }).catch(err => console.log('Error: ', err))

}
function mostrarFormulario() {
    // Mostrar el formulario al hacer clic en el botón
    if(document.getElementById("formulario").style.display == "none"){
        document.getElementById("formulario").style.display = "block";
    }else{
        document.getElementById("formulario").style.display = "none";
    }
    
}

function agregarSolicitud(event) {
    event.preventDefault();

    const userId = document.getElementById("userId").value;
    const itemId = document.getElementById("itemId").value;

    axios.post('http://127.0.0.1:5000/insertar/solicitud', {
        userId: userId,
        itemId: itemId
    }, {
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        alert("Solicitud creada exitosamente.");
    })
    .catch(error => {
        alert("Ocurrió un error al crear la solicitud.")
        alert(nombre,itemId)
    });
    document.getElementById("formulario").style.display = "none";
}
