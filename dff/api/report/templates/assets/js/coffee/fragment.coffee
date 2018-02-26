namespace "fragments"
  FObject:
    class FObject
      constructor: (@json, @id) ->
        @rootDom = null
        @html = $('<div>').addClass('container fragment')
          .attr('id', @id.toString())
    
      setTitle: () ->
          @rootDom.append($('<h2>').append(@json.title))

      render: (root) ->
        if root
          @rootDom = root
          if @json.title then @setTitle(root)
          @rootDom.append(@html)
          
      clear: () ->
#        console.log @rootDom
        @rootDom.empty()
      

            