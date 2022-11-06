function init() {
    let socials = document.getElementsByClassName("btn-social");
    for(let social of socials){
        social.addEventListener("click", function (){
            let socialType = this.getAttribute('data-social');
            location.href="/oauth2/authorization/"+socialType;
        })
    }
}

init();


