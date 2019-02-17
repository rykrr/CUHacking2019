



var ctx = $("#line-chart");

var lineChart = new Chart(ctx, {

    type: 'line', 
    data: {
    labels: ["A"], 
    datasets: [
    {
        label: "2019",
        data: [1, 2, 3, 4, 5, 6, 7]
                 }
                ]
             }
         });




