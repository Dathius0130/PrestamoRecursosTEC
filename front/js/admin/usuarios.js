infoForm={};    // para la tabla.
tabla = document.getElementById("tablausuario"); // tabla 

function consultar_user(){
    axios({
        methods: 'GET',
        url: 'http://127.0.0.1:5000/usuarios',

    }).then(function (response){

        for (let i = 0; i < response.data.length; i++){

            let nuevaFila = tabla.insertRow(tabla.length);

            cell0 = nuevaFila.insertCell(0);
            cell0.innerHTML = response.data[i].userId;

            cell1 = nuevaFila.insertCell(1);
            cell1.innerHTML = response.data[i].usuario;

            cell2 = nuevaFila.insertCell(2);
            cell2.innerHTML = response.data[i].nombre;

            cell3 = nuevaFila.insertCell(3);
            cell3.innerHTML = response.data[i].apellido;

            cell4 = nuevaFila.insertCell(4);
            cell4.innerHTML = response.data[i].identificacion;

            cell5 = nuevaFila.insertCell(5);
            cell5.innerHTML = response.data[i].correo;

            cell6 = nuevaFila.insertCell(6);
            cell6.innerHTML = response.data[i].perfil;

            cell7 = nuevaFila.insertCell(7);
            cell7.innerHTML = response.data[i].password;

            cell8 = nuevaFila.insertCell(8);
            cell8.innerHTML = `<a class="btn btn-warning mx-5 " onClick="onEdit(this)">Editar</a>`;
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

function agregarUsuario(event) {
    event.preventDefault();

    const usuario = document.getElementById("usuario").value;
    const nombre = document.getElementById("nombre").value;
    const apellido = document.getElementById("apellido").value;
    const identificacion = document.getElementById("identificacion").value;
    const correo = document.getElementById("correo").value;
    const perfilId = document.getElementById("perfilId").value;
    const password = document.getElementById("password").value;

    axios.post('http://127.0.0.1:5000/insertar/usuario', {
        usuario: usuario,
        nombre: nombre,
        apellido: apellido,
        identificacion: identificacion,
        correo: correo,
        perfilId: perfilId,
        password: password
    }, {
        headers: {
            'Content-Type': 'application/json'
        }
    })
    .then(response => {
        alert("Usuario creado exitosamente.");
    })
    .catch(error => {
        alert("Ocurrió un error al crear el usuario.")
    });
    document.getElementById("formulario").style.display = "none";
}