namespace "fragments"
  TextFragment:
    class TextFragment extends fragments.FObject
      constructor: (@fragment, @id) ->
        super
        @html.append($('<p>').append(@fragment.data))

  
      render: (root) ->
        super
  