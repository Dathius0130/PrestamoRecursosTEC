infoForm={};    // para la tabla.
tabla = document.getElementById("tablainventario"); // tabla 

function consultar_inventario(){
    axios({
        methods: 'GET',
        url: 'http://127.0.0.1:5000/inventario',

    }).then(function (response){

        for (let i = 0; i < response.data.length; i++){

            let nuevaFila = tabla.insertRow(tabla.length);

            cell0 = nuevaFila.insertCell(0);
            cell0.innerHTML = response.data[i].inventario;

            cell1 = nuevaFila.insertCell(1);
            cell1.innerHTML = response.data[i].item;

            cell2 = nuevaFila.insertCell(2);
            cell2.innerHTML = response.data[i].cantidad;

            cell3 = nuevaFila.insertCell(3);
            cell3.innerHTML = response.data[i].cantidad_disponible;
            if(cell3.innerHTML==0){
                cell3.innerHTML= '<h4>No hay disponibles</h4>'
            }else{
                cell3.innerHTML = response.data[i].cantidad_disponible;
            }

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
function agregarInv(event) {
    event.preventDefault();
    const itemId = document.getElementById("itemid").value;
    const cantidad = document.getElementById("cantidad").value;

    axios.post('http://127.0.0.1:5000/insertar/inventario', {
        cantidad: cantidad,
        itemId: itemId
    }).then(function (response) {
        alert("Item añadido al inventario exitosamente.");
    }).catch(function (error) {
        alert("Ocurrió un error al añadir el item.");
    });
    
    document.getElementById("formulario").style.display = "none";
}
