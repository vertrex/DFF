var map;
var markers=[];
var markerClusterer = null;
var geocoder;

function initialize() 
{
  var myOptions = 
  {
    zoom: 0,
    mapTypeId: google.maps.MapTypeId.ROADMAP
  };

  var div = document.getElementById("map_canvas");
  map = new google.maps.Map(div, myOptions);
  geocoder = new google.maps.Geocoder;
}

function gmap_refreshMap() 
{
  var allMarkers = [];
  for (k in markers) 
  {
    allMarkers.push(markers[k]); 
  }
  var options = {
	imagePath: 'images/m'
  };
  var markerCluster = new MarkerClusterer(map, allMarkers, options);
}

function gmap_setCenter(lat, lng)
{
  map.setCenter(new google.maps.LatLng(lat, lng));
}

function gmap_getCenter()
{
  return map.getCenter();
}

function gmap_setZoom(zoom)
{
  map.setZoom(zoom);
}

function gmap_addMarker(key, latitude, longitude, parameters)
{
  var marker = new google.maps.Marker({
     map:map,
     position: {lat: latitude, lng:longitude},
     title: parameters["name"],
     });

  google.maps.event.addListener(marker, 'click', function() 
  {
    qtWidget.markerClicked(key, marker.position.lat(), marker.position.lng())
  });

  /*var results, status = geocoder.geocode({'location' : {lat : latitude, lng:longitude} }, function(results, status)*/
  /*{*/
  /*console.log(status)*/
  /*console.log(results)*/
  /*});*/

  markers[key] = marker;
  return key;
}

function gmap_deleteMarker(key)
{
  markers[key].setMap(null);
  delete markers[key]
}

function gmap_changeMarker(key, extras)
{
  if (!(key in markers)) 
  {
    return
  }
  markers[key].setOptions(extras);
}
