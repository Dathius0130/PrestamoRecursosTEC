function login() {
    var user, password;
    user = document.getElementById("user").value;
    password = document.getElementById("password").value;

    // Agregar una solicitud HTTP POST para buscar el usuario y la contraseña
    axios.post('http://127.0.0.1:5000/Login', {
        usuario: user,
        password: password
    })
    .then(function (response) {
        if (response.status === 200) {
            // El inicio de sesión fue exitoso
            // Obtener el perfil del usuario de la respuesta
            var perfil = response.data.Perfil;
            // Redirigir a diferentes páginas según el perfil
            if (perfil === 1) {
                window.location = "admin.html";
            } else if (perfil === 2) {
                window.location = "usuario.html";
            } else {
                alert("Perfil no válido");
            }
        } else {
            alert("Hubo un problema al intentar iniciar sesión");
        }
    })
    .catch(function (error) {
        alert("Inicio de Sesión Fallido");
        console.log(error);
    });
}
