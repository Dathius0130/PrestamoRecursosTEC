infoForm={};    // para la tabla.
tabla = document.getElementById("tablaitem"); // tabla 

function consultar_item(){
    axios({
        methods: 'GET',
        url: 'http://127.0.0.1:5000/items',

    }).then(function (response){

        for (let i = 0; i < response.data.length; i++){

            let nuevaFila = tabla.insertRow(tabla.length);

            cell0 = nuevaFila.insertCell(0);
            cell0.innerHTML = response.data[i].itemid;

            cell1 = nuevaFila.insertCell(1);
            cell1.innerHTML = response.data[i].item;

            cell2 = nuevaFila.insertCell(2);
            cell2.innerHTML = response.data[i].descripcion;

            cell3 = nuevaFila.insertCell(3);
            cell3.innerHTML = response.data[i].tipo;

            cell4 = nuevaFila.insertCell(4);
            cell4.innerHTML = `<a class="btn btn-warning mx-5 " onClick="onEdit(this)">Editar</a>`;
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

function agregarItem(event) {
    event.preventDefault();

    const nombre = document.getElementById("nombre").value;
    const descripcion = document.getElementById("descripcion").value;
    const tipo = document.getElementById("tipo").value;

    axios.post('http://127.0.0.1:5000/insertar/item', {
        nombre: nombre,
        descripcion: descripcion,
        tipo: tipo
    }, {
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        alert("Item creado exitosamente.");
    })
    .catch(error => {
        alert("Ocurrió un error al crear el item.")
    });
    document.getElementById("formulario").style.display = "none";
}
