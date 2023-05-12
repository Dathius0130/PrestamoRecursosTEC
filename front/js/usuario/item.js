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

        }

    }).catch(err => console.log('Error: ', err))

}