$(document).ready(function(){
    $("#status_code").change(function(){
        if($(this).val() === "plus"){
             $(".value200").show();
             $(".value403").hide();
             $(".value300").hide();
             $(".value4500").hide();
         }
         else if($(this).val() === "redirect"){
             $(".value300").show();
             $(".value200").hide();
             $(".value403").hide();
             $(".value4500").hide();
         }
         else if($(this).val() === "forbi"){
             $(".value403").show();
             $(".value200").hide();
             $(".value300").hide();
             $(".value4500").hide();
         }
         else if($(this).val() === "serv_error"){
             $(".value403").hide();
             $(".value200").hide();
             $(".value300").hide();
             $(".value4500").show();
         }
         else{
             $(".value200").show();
             $(".value403").show();
         }
    });
});


