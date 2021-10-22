$(function(){
    
    // firebase auth setup
    const firebaseConfig = {
        apiKey: "AIzaSyAvvEBIbeIN8RrBcyD8sK5h3nr22Fe5xt4",
        authDomain: "fir-admin-auth-rs-test.firebaseapp.com",
        projectId: "fir-admin-auth-rs-test",
        storageBucket: "fir-admin-auth-rs-test.appspot.com",
        messagingSenderId: "227474888386",
        appId: "1:227474888386:web:3c76480aabd0e53a920d5b"
    };
    let userIdToken = null;
    firebase.initializeApp(firebaseConfig);
    // if (!firebase.auth().currentUser) {
    firebase.auth().onAuthStateChanged(function(user) {
        if (user) {
            $('#loggedout').hide();
            user.getIdToken().then(function(idToken) {
                userIdToken = idToken;
                $('#user').text(user.displayName);
                $('#loggedin').show();
            });

        } else {
            $('#loggedin').hide();
            $('#loggedout').show();
        }
    });

    // firebase UI setup
    const uiConfig = {
        signInSuccessUrl: '/index.html',
        signInOptions: [
            {
                provider: firebase.auth.GoogleAuthProvider.PROVIDER_ID,
                scopes: [
                    'https://www.googleapis.com/auth/contacts.readonly'
                ],
                customParameters: {
                    prompt: 'select_account'
                }
            }
        ]
    };
    const ui = new firebaseui.auth.AuthUI(firebase.auth());
    ui.start('#firebaseui-auth-container', uiConfig);

    // handle events
    const logoutButton = $('#logout-button');
    logoutButton.click(function(event) {
        event.preventDefault();
        firebase.auth().signOut().then(function() {
            location.reload();
        }, function(e) {
            console.error(e);
        });
    });
    const baseUrl = "http://localhost:8080"
    const getUidButton = $('#get-uid-button');
    getUidButton.click(function(event) {
        event.preventDefault();
        $.ajax(baseUrl + '/uid', {
            headers: {
                'Authorization': 'Bearer ' + userIdToken
            }
        }).then(function(_, _, jqXHR){
            console.log(jqXHR)
            $('#responses').append($('<p>').text(`[info] ${jqXHR.status} ${jqXHR.statusText}: ${jqXHR.responseText}`));
        }).catch(function(_, _, jqXHR){
            $('#responses').append($('<p>').text(`[error] ${jqXHR.status} ${jqXHR.statusText}: ${jqXHR.responseText}`));
        });
    });

});