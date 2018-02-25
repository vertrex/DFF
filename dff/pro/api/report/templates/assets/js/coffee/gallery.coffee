namespace "fragments"
  NodeGalleryFragment:
    class NodeGalleryFragment extends fragments.FObject
      constructor: (@json, @id) ->
        super @json, @id
        console.log @json.view
        @container = $('<div>').addClass('container')
        @max_visible_pages = 6
        @visible_items = 14
        @current_page = 0

      configurePagination: () ->
        @pages = parseInt((@json.data.length / @visible_items))
        @pages = @pages + 1 if @json.data.length % @visible_items > 0
        @pages = @pages - 1
        @pages = 0 if @pages < 0

      pagination: () ->
        $('div.row-fluid#pagination').remove()
        paginate = $('<div>').addClass("row-fluid").attr("id", "pagination")
        div_pages = $('<div>').addClass("pagination pagination-centered")
        ul = $('<ul>').attr("id", "pagination")
        start = @current_page - (@current_page % @max_visible_pages)
        end = start + @max_visible_pages
        stop = if end > @pages then @pages else end
        @previous ul
        for num in [start..stop]
          link = $('<a>').attr('href', '#').append(num + 1)
          link.bind 'click' , (event) =>
            @current_page = parseInt($(event.target).text()) - 1
            @refresh()
          if num is @current_page    
            ul.append($('<li>').addClass('active').append(link))
          else
            ul.append($('<li>').append(link))

        @next(ul)
        div_pages.append(ul)
        paginate.append(div_pages)
        @container.append(paginate)

      next: (ul) ->
        li = $('<li>')
        a = $('<a>').attr("href", "#").append(">>")
        if @current_page is @pages
          li.addClass('disabled')
        else
          a.bind 'click' , (event) =>
            @current_page = @current_page + 1
            @refresh()
        ul.append(li.append(a))

      previous: (ul) ->
        li = $('<li>')
        a = $('<a>').attr("href", "#").append("<<")
        if @current_page is 0
          li.addClass('disabled')
        else
          a.bind 'click' , (event) =>
            @current_page = @current_page - 1
            @refresh()
        ul.append(li.append(a))

      createGallery: () ->
        $('ul.thumbnails').remove()
        data = @json.data
        start = @current_page * @visible_items
        start = if @current_page > 0 then start + 1 else start
        end = start + @visible_items
        stop = if end > data.length then data.length else end
        sdata = data[start..stop]
        thumbnails = $('<ul>').addClass('thumbnails')
          .append($('<div>').addClass("span").attr("style", "display: none;"))
        for img in sdata
          li = $('<li>').addClass('span2')
            .append $('<a>').addClass('thumbnail').attr('href', img.file)
              .append $('<img>').attr('src', img.thumb).attr('style', 'width: 128px; height:128px;')
          thumbnails.append li
    
        @container.append(thumbnails)

      refresh: () ->
        @configurePagination()
        @createGallery()
        @pagination()

      #### Table
      render: (rootDom) =>
        super
        @html.append(@container)
